use crate::interpreter::{
    analysis::to_analysed, gas, instruction_result::SuccessOrHalt, return_ok, return_revert,
    CallContext, CallInputs, CallScheme, Contract, CreateInputs, CreateScheme, Gas, Host,
    InstructionResult, Interpreter, SelfDestructResult, Transfer, CALL_STACK_LIMIT,
};
use crate::journaled_state::is_precompile;
use crate::primitives::{
    create2_address, create_address, keccak256, Account, AnalysisKind, Bytecode, Bytes, EVMError,
    EVMResult, Env, ExecutionResult, HashMap, InvalidTransaction, Log, Output, ResultAndState,
    Spec,
    SpecId::{self, *},
    TransactTo, B160, B256, U256,
};
use crate::{db::Database, journaled_state::JournaledState, precompile, Inspector};
use alloc::vec::Vec;
use core::{cmp::min, marker::PhantomData};
use std::sync::Arc;
use revm_interpreter::gas::initial_tx_gas;
use revm_interpreter::{BytecodeLocked, MAX_CODE_SIZE};
use revm_precompile::{Precompile, Precompiles};

pub struct EVMData<'a, DB: Database> {
    pub env: &'a mut Env,
    pub journaled_state: JournaledState,
    pub db: &'a mut DB,
    pub error: Option<DB::Error>,
}

pub struct EVMImpl<'a, GSPEC: Spec, DB: Database, const INSPECT: bool> {
    data: EVMData<'a, DB>,
    precompiles: Precompiles,
    inspector: &'a mut dyn Inspector<DB>,
    _phantomdata: PhantomData<GSPEC>,
}

pub trait Transact<DBError> {
    /// Do transaction.
    /// InstructionResult InstructionResult, Output for call or Address if we are creating
    /// contract, gas spend, gas refunded, State that needs to be applied.
    fn transact(&mut self) -> EVMResult<DBError>;
}

impl<'a, GSPEC: Spec, DB: Database, const INSPECT: bool> EVMImpl<'a, GSPEC, DB, INSPECT> {
    /// Load access list for berlin hardfork.
    ///
    /// Loading of accounts/storages is needed to make them hot.
    #[inline]
    fn load_access_list(&mut self) -> Result<(), EVMError<DB::Error>> {
        for (address, slots) in self.data.env.tx.access_list.iter() {
            self.data
                .journaled_state
                .initial_account_load(*address, slots, self.data.db)
                .map_err(EVMError::Database)?;
        }
        Ok(())
    }
}

impl<'a, GSPEC: Spec, DB: Database, const INSPECT: bool> Transact<DB::Error>
    for EVMImpl<'a, GSPEC, DB, INSPECT>
{
    fn transact(&mut self) -> EVMResult<DB::Error> {
        self.env().validate_block_env::<GSPEC, DB::Error>()?;
        self.env().validate_tx::<GSPEC>()?;

        let env = &self.data.env;
        let tx_caller = env.tx.caller;
        let tx_value = env.tx.value;
        let tx_data = env.tx.data.clone();
        let tx_gas_limit = env.tx.gas_limit;
        let tx_is_create = env.tx.transact_to.is_create();
        let effective_gas_price = env.effective_gas_price();

        let initial_gas_spend =
            initial_tx_gas::<GSPEC>(&tx_data, tx_is_create, &env.tx.access_list);

        // Additonal check to see if limit is big enought to cover initial gas.
        if env.tx.gas_limit < initial_gas_spend {
            return Err(InvalidTransaction::CallGasCostMoreThanGasLimit.into());
        }

        // load coinbase
        // EIP-3651: Warm COINBASE. Starts the `COINBASE` address warm
        if GSPEC::enabled(SHANGHAI) {
            self.data
                .journaled_state
                .initial_account_load(self.data.env.block.coinbase, &[], self.data.db)
                .map_err(EVMError::Database)?;
        }
        self.load_access_list()?;

        // load acc
        let journal = &mut self.data.journaled_state;
        let (caller_account, _) = journal
            .load_account(tx_caller, self.data.db)
            .map_err(EVMError::Database)?;

        self.data.env.validate_tx_agains_state(caller_account)?;

        // Reduce gas_limit*gas_price amount of caller account.
        // unwrap_or can only occur if disable_balance_check is enabled
        caller_account.info.balance = caller_account
            .info
            .balance
            .checked_sub(U256::from(tx_gas_limit).saturating_mul(effective_gas_price))
            .unwrap_or(U256::ZERO);

        // touch account so we know it is changed.
        caller_account.mark_touch();

        let transact_gas_limit = tx_gas_limit - initial_gas_spend;

        // call inner handling of call/create
        let (exit_reason, ret_gas, output) = match self.data.env.tx.transact_to {
            TransactTo::Call(address) => {
                // Nonce is already checked
                caller_account.info.nonce =
                    caller_account.info.nonce.checked_add(1).unwrap_or(u64::MAX);

                let (exit, gas, bytes) = self.call(&mut CallInputs {
                    contract: address,
                    transfer: Transfer {
                        source: tx_caller,
                        target: address,
                        value: tx_value,
                    },
                    input: tx_data,
                    gas_limit: transact_gas_limit,
                    context: CallContext {
                        caller: tx_caller,
                        address,
                        code_address: address,
                        apparent_value: tx_value,
                        scheme: CallScheme::Call,
                    },
                    is_static: false,
                },&mut Interpreter::new(Contract::default(), 0, false),  (0,0),&mut 0
                );
                (exit, gas, Output::Call(bytes))
            }
            TransactTo::Create(scheme) => {
                let (exit, address, ret_gas, bytes) = self.create(&mut CreateInputs {
                    caller: tx_caller,
                    scheme,
                    value: tx_value,
                    init_code: tx_data,
                    gas_limit: transact_gas_limit,
                }, &mut 0);
                (exit, ret_gas, Output::Create(bytes, address))
            }
        };

        // set gas with gas limit and spend it all. Gas is going to be reimbursed when
        // transaction is returned successfully.
        let mut gas = Gas::new(tx_gas_limit);
        gas.record_cost(tx_gas_limit);

        if crate::USE_GAS {
            match exit_reason {
                return_ok!() => {
                    gas.erase_cost(ret_gas.remaining());
                    gas.record_refund(ret_gas.refunded());
                }
                return_revert!() => {
                    gas.erase_cost(ret_gas.remaining());
                }
                _ => {}
            }
        }

        let (state, logs, gas_used, gas_refunded) = self.finalize::<GSPEC>(&gas);

        let result = match exit_reason.into() {
            SuccessOrHalt::Success(reason) => ExecutionResult::Success {
                reason,
                gas_used,
                gas_refunded,
                logs,
                output,
            },
            SuccessOrHalt::Revert => ExecutionResult::Revert {
                gas_used,
                output: match output {
                    Output::Call(return_value) => return_value,
                    Output::Create(return_value, _) => return_value,
                },
            },
            SuccessOrHalt::Halt(reason) => ExecutionResult::Halt { reason, gas_used },
            SuccessOrHalt::FatalExternalError => {
                return Err(EVMError::Database(self.data.error.take().unwrap()))
            }
            SuccessOrHalt::InternalContinue => {
                panic!("Internal return flags should remain internal {exit_reason:?}")
            }
        };

        Ok(ResultAndState { result, state })
    }
}

impl<'a, GSPEC: Spec, DB: Database, const INSPECT: bool> EVMImpl<'a, GSPEC, DB, INSPECT> {
    pub fn new(
        db: &'a mut DB,
        env: &'a mut Env,
        inspector: &'a mut dyn Inspector<DB>,
        precompiles: Precompiles,
    ) -> Self {
        let journaled_state = if GSPEC::enabled(SpecId::SPURIOUS_DRAGON) {
            JournaledState::new(precompiles.len())
        } else {
            JournaledState::new_legacy(precompiles.len())
        };
        Self {
            data: EVMData {
                env,
                journaled_state,
                db,
                error: None,
            },
            precompiles,
            inspector,
            _phantomdata: PhantomData {},
        }
    }

    fn finalize<SPEC: Spec>(&mut self, gas: &Gas) -> (HashMap<B160, Account>, Vec<Log>, u64, u64) {
        let caller = self.data.env.tx.caller;
        let coinbase = self.data.env.block.coinbase;
        let (gas_used, gas_refunded) = if crate::USE_GAS {
            let effective_gas_price = self.data.env.effective_gas_price();
            let basefee = self.data.env.block.basefee;

            let gas_refunded = if self.env().cfg.is_gas_refund_disabled() {
                0
            } else {
                // EIP-3529: Reduction in refunds
                let max_refund_quotient = if SPEC::enabled(LONDON) { 5 } else { 2 };
                min(gas.refunded() as u64, gas.spend() / max_refund_quotient)
            };

            // return balance of not spend gas.
            let caller_account = self.data.journaled_state.state().get_mut(&caller).unwrap();
            caller_account.info.balance = caller_account
                .info
                .balance
                .saturating_add(effective_gas_price * U256::from(gas.remaining() + gas_refunded));

            // EIP-1559 discard basefee for coinbase transfer. Basefee amount of gas is discarded.
            let coinbase_gas_price = if SPEC::enabled(LONDON) {
                effective_gas_price.saturating_sub(basefee)
            } else {
                effective_gas_price
            };

            // transfer fee to coinbase/beneficiary.
            let Ok((coinbase_account,_)) = self
                .data
                .journaled_state
                .load_account(coinbase, self.data.db) else { panic!("coinbase account not found");};
            coinbase_account.mark_touch();
            coinbase_account.info.balance = coinbase_account
                .info
                .balance
                .saturating_add(coinbase_gas_price * U256::from(gas.spend() - gas_refunded));

            (gas.spend() - gas_refunded, gas_refunded)
        } else {
            // touch coinbase
            let _ = self
                .data
                .journaled_state
                .load_account(coinbase, self.data.db);
            self.data.journaled_state.touch(&coinbase);
            (0, 0)
        };
        let (new_state, logs) = self.data.journaled_state.finalize();
        (new_state, logs, gas_used, gas_refunded)
    }

    /// EVM create opcode for both initial crate and CREATE and CREATE2 opcodes.
    fn create_inner(
        &mut self,
        inputs: &CreateInputs,
    ) -> (InstructionResult, Option<B160>, Gas, Bytes) {
        let gas = Gas::new(inputs.gas_limit);

        // Check depth of calls
        if self.data.journaled_state.depth() > CALL_STACK_LIMIT {
            return (InstructionResult::CallTooDeep, None, gas, Bytes::new());
        }

        // Fetch balance of caller.
        let Some((caller_balance,_)) = self.balance(inputs.caller) else {
            return (InstructionResult::FatalExternalError, None, gas, Bytes::new())
        };

        // Check if caller has enough balance to send to the crated contract.
        if caller_balance < inputs.value {
            return (InstructionResult::OutOfFund, None, gas, Bytes::new());
        }

        // Increase nonce of caller and check if it overflows
        let old_nonce;
        if let Some(nonce) = self.data.journaled_state.inc_nonce(inputs.caller) {
            old_nonce = nonce - 1;
        } else {
            return (InstructionResult::Return, None, gas, Bytes::new());
        }

        // Create address
        let code_hash = keccak256(&inputs.init_code);
        let created_address = match inputs.scheme {
            CreateScheme::Create => create_address(inputs.caller, old_nonce),
            CreateScheme::Create2 { salt } => create2_address(inputs.caller, code_hash, salt),
        };
        let ret = Some(created_address);

        // Load account so it needs to be marked as hot for access list.
        if self
            .data
            .journaled_state
            .load_account(created_address, self.data.db)
            .map_err(|e| self.data.error = Some(e))
            .is_err()
        {
            return (
                InstructionResult::FatalExternalError,
                None,
                gas,
                Bytes::new(),
            );
        }

        // create account, transfer funds and make the journal checkpoint.
        let checkpoint = match self
            .data
            .journaled_state
            .create_account_checkpoint::<GSPEC>(inputs.caller, created_address, inputs.value)
        {
            Ok(checkpoint) => checkpoint,
            Err(e) => return (e, None, gas, Bytes::new()),
        };

        // Create new interpreter and execute initcode
        let (exit_reason, mut interpreter) = self.run_interpreter(
            Contract::new(
                Bytes::new(),
                Bytecode::new_raw(inputs.init_code.clone()),
                created_address,
                created_address,
                inputs.caller,
                inputs.value,
            ),
            gas.limit(),
            false,
        );

        // Host error if present on execution
        match exit_reason {
            return_ok!() => {
                // if ok, check contract creation limit and calculate gas deduction on output len.
                let mut bytes = interpreter.return_value();

                // EIP-3541: Reject new contract code starting with the 0xEF byte
                if GSPEC::enabled(LONDON) && !bytes.is_empty() && bytes.first() == Some(&0xEF) {
                    self.data.journaled_state.checkpoint_revert(checkpoint);
                    return (
                        InstructionResult::CreateContractStartingWithEF,
                        ret,
                        interpreter.gas,
                        bytes,
                    );
                }

                // EIP-170: Contract code size limit
                // By default limit is 0x6000 (~25kb)
                if GSPEC::enabled(SPURIOUS_DRAGON)
                    && bytes.len()
                        > self
                            .data
                            .env
                            .cfg
                            .limit_contract_code_size
                            .unwrap_or(MAX_CODE_SIZE)
                {
                    self.data.journaled_state.checkpoint_revert(checkpoint);
                    return (
                        InstructionResult::CreateContractSizeLimit,
                        ret,
                        interpreter.gas,
                        bytes,
                    );
                }
                if crate::USE_GAS {
                    let gas_for_code = bytes.len() as u64 * gas::CODEDEPOSIT;
                    if !interpreter.gas.record_cost(gas_for_code) {
                        // record code deposit gas cost and check if we are out of gas.
                        // EIP-2 point 3: If contract creation does not have enough gas to pay for the
                        // final gas fee for adding the contract code to the state, the contract
                        //  creation fails (i.e. goes out-of-gas) rather than leaving an empty contract.
                        if GSPEC::enabled(HOMESTEAD) {
                            self.data.journaled_state.checkpoint_revert(checkpoint);
                            return (InstructionResult::OutOfGas, ret, interpreter.gas, bytes);
                        } else {
                            bytes = Bytes::new();
                        }
                    }
                }
                // if we have enough gas
                self.data.journaled_state.checkpoint_commit();
                // Do analysis of bytecode straight away.
                let bytecode = match self.data.env.cfg.perf_analyse_created_bytecodes {
                    AnalysisKind::Raw => Bytecode::new_raw(bytes.clone()),
                    AnalysisKind::Check => Bytecode::new_raw(bytes.clone()).to_checked(),
                    AnalysisKind::Analyse => to_analysed(Bytecode::new_raw(bytes.clone())),
                };
                self.data
                    .journaled_state
                    .set_code(created_address, bytecode);
                (InstructionResult::Return, ret, interpreter.gas, bytes)
            }
            _ => {
                self.data.journaled_state.checkpoint_revert(checkpoint);
                (
                    exit_reason,
                    ret,
                    interpreter.gas,
                    interpreter.return_value(),
                )
            }
        }
    }

    /// Create a Interpreter and run it.
    /// Returns the exit reason and created interpreter as it contains return values and gas spend.
    pub fn run_interpreter(
        &mut self,
        contract: Contract,
        gas_limit: u64,
        is_static: bool,
    ) -> (InstructionResult, Interpreter) {
        // Create inspector
        #[cfg(feature = "memory_limit")]
        let mut interpreter = Interpreter::new_with_memory_limit(
            contract,
            gas_limit,
            is_static,
            self.data.env.cfg.memory_limit,
        );

        #[cfg(not(feature = "memory_limit"))]
        let mut interpreter = Interpreter::new(contract, gas_limit, is_static);

        if INSPECT {
            self.inspector
                .initialize_interp(&mut interpreter, &mut self.data);
        }
        let exit_reason = if INSPECT {
            interpreter.run_inspect::<u32, Self, GSPEC>(self, &mut 0)
        } else {
            interpreter.run::<u32, Self, GSPEC>(self, &mut 0)
        };

        (exit_reason, interpreter)
    }

    /// Call precompile contract
    fn call_precompile(
        &mut self,
        mut gas: Gas,
        contract: B160,
        input_data: Bytes,
    ) -> (InstructionResult, Gas, Bytes) {
        let precompile = self
            .precompiles
            .get(&contract)
            .expect("Check for precompile should be already done");
        let out = match precompile {
            Precompile::Standard(fun) => fun(&input_data, gas.limit()),
            Precompile::Custom(fun) => fun(&input_data, gas.limit()),
        };
        match out {
            Ok((gas_used, data)) => {
                if !crate::USE_GAS || gas.record_cost(gas_used) {
                    (InstructionResult::Return, gas, Bytes::from(data))
                } else {
                    (InstructionResult::PrecompileOOG, gas, Bytes::new())
                }
            }
            Err(e) => {
                let ret = if precompile::Error::OutOfGas == e {
                    InstructionResult::PrecompileOOG
                } else {
                    InstructionResult::PrecompileError
                };
                (ret, gas, Bytes::new())
            }
        }
    }

    /// Main contract call of the EVM.
    fn call_inner(&mut self, inputs: &mut CallInputs) -> (InstructionResult, Gas, Bytes) {
        let gas = Gas::new(inputs.gas_limit);
        // Load account and get code. Account is now hot.
        let Some((bytecode,_)) = self.code(inputs.contract) else {
            return (InstructionResult::FatalExternalError, gas, Bytes::new());
        };

        // Check depth
        if self.data.journaled_state.depth() > CALL_STACK_LIMIT {
            return (InstructionResult::CallTooDeep, gas, Bytes::new());
        }

        // Create subroutine checkpoint
        let checkpoint = self.data.journaled_state.checkpoint();

        // Touch address. For "EIP-158 State Clear", this will erase empty accounts.
        if inputs.transfer.value == U256::ZERO {
            self.load_account(inputs.context.address);
            self.data.journaled_state.touch(&inputs.context.address);
        }

        // Transfer value from caller to called account
        if let Err(e) = self.data.journaled_state.transfer(
            &inputs.transfer.source,
            &inputs.transfer.target,
            inputs.transfer.value,
            self.data.db,
        ) {
            self.data.journaled_state.checkpoint_revert(checkpoint);
            return (e, gas, Bytes::new());
        }

        let ret = if is_precompile(inputs.contract, self.precompiles.len()) {
            self.call_precompile(gas, inputs.contract, inputs.input.clone())
        } else if !bytecode.is_empty() {
            // Create interpreter and execute subcall
            let (exit_reason, interpreter) = self.run_interpreter(
                Contract::new_with_context_analyzed(inputs.input.clone(), bytecode, &inputs.context),
                gas.limit(),
                inputs.is_static,
            );
            (exit_reason, interpreter.gas, interpreter.return_value())
        } else {
            (InstructionResult::Stop, gas, Bytes::new())
        };

        // revert changes or not.
        if matches!(ret.0, return_ok!()) {
            self.data.journaled_state.checkpoint_commit();
        } else {
            self.data.journaled_state.checkpoint_revert(checkpoint);
        }

        ret
    }
}

impl<'a, GSPEC: Spec, DB: Database + 'a, const INSPECT: bool> Host<u32>
    for EVMImpl<'a, GSPEC, DB, INSPECT>
{
    fn step(&mut self, interp: &mut Interpreter, _: &mut u32) -> InstructionResult {
        self.inspector.step(interp, &mut self.data)
    }

    fn step_end(&mut self, interp: &mut Interpreter, ret: InstructionResult, _: &mut u32) -> InstructionResult {
        self.inspector.step_end(interp, &mut self.data, ret)
    }

    fn env(&mut self) -> &mut Env {
        self.data.env
    }

    fn block_hash(&mut self, number: U256) -> Option<B256> {
        self.data
            .db
            .block_hash(number)
            .map_err(|e| self.data.error = Some(e))
            .ok()
    }

    fn load_account(&mut self, address: B160) -> Option<(bool, bool)> {
        self.data
            .journaled_state
            .load_account_exist(address, self.data.db)
            .map_err(|e| self.data.error = Some(e))
            .ok()
    }

    fn balance(&mut self, address: B160) -> Option<(U256, bool)> {
        let db = &mut self.data.db;
        let journal = &mut self.data.journaled_state;
        let error = &mut self.data.error;
        journal
            .load_account(address, db)
            .map_err(|e| *error = Some(e))
            .ok()
            .map(|(acc, is_cold)| (acc.info.balance, is_cold))
    }

    fn code(&mut self, address: B160) -> Option<(Arc<BytecodeLocked>, bool)> {
        let journal = &mut self.data.journaled_state;
        let db = &mut self.data.db;
        let error = &mut self.data.error;

        let (acc, is_cold) = journal
            .load_code(address, db)
            .map_err(|e| *error = Some(e))
            .ok()?;
        Some((Arc::new(BytecodeLocked::default()), is_cold))
    }

    /// Get code hash of address.
    fn code_hash(&mut self, address: B160) -> Option<(B256, bool)> {
        let journal = &mut self.data.journaled_state;
        let db = &mut self.data.db;
        let error = &mut self.data.error;

        let (acc, is_cold) = journal
            .load_code(address, db)
            .map_err(|e| *error = Some(e))
            .ok()?;

        if acc.is_empty() {
            return Some((B256::zero(), is_cold));
        }

        Some((acc.info.code_hash, is_cold))
    }

    fn sload(&mut self, address: B160, index: U256) -> Option<(U256, bool)> {
        // account is always hot. reference on that statement https://eips.ethereum.org/EIPS/eip-2929 see `Note 2:`
        self.data
            .journaled_state
            .sload(address, index, self.data.db)
            .map_err(|e| self.data.error = Some(e))
            .ok()
    }

    fn sstore(
        &mut self,
        address: B160,
        index: U256,
        value: U256,
    ) -> Option<(U256, U256, U256, bool)> {
        self.data
            .journaled_state
            .sstore(address, index, value, self.data.db)
            .map_err(|e| self.data.error = Some(e))
            .ok()
    }

    fn log(&mut self, address: B160, topics: Vec<B256>, data: Bytes) {
        if INSPECT {
            self.inspector.log(&mut self.data, &address, &topics, &data);
        }
        let log = Log {
            address,
            topics,
            data,
        };
        self.data.journaled_state.log(log);
    }

    fn selfdestruct(&mut self, address: B160, target: B160) -> Option<SelfDestructResult> {
        if INSPECT {
            self.inspector.selfdestruct(address, target);
        }
        self.data
            .journaled_state
            .selfdestruct(address, target, self.data.db)
            .map_err(|e| self.data.error = Some(e))
            .ok()
    }

    fn create(
        &mut self,
        inputs: &mut CreateInputs,
        _: &mut u32
    ) -> (InstructionResult, Option<B160>, Gas, Bytes) {
        // Call inspector
        if INSPECT {
            let (ret, address, gas, out) = self.inspector.create(&mut self.data, inputs);
            if ret != InstructionResult::Continue {
                return (ret, address, gas, out);
            }
        }
        let ret = self.create_inner(inputs);
        if INSPECT {
            self.inspector
                .create_end(&mut self.data, inputs, ret.0, ret.1, ret.2, ret.3)
        } else {
            ret
        }
    }

    fn call(&mut self, inputs: &mut CallInputs, _: &mut Interpreter, output_info: (usize, usize), _: &mut u32) -> (InstructionResult, Gas, Bytes) {
        if INSPECT {
            let (ret, gas, out) = self.inspector.call(&mut self.data, inputs);
            if ret != InstructionResult::Continue {
                return (ret, gas, out);
            }
        }
        let ret = self.call_inner(inputs);
        if INSPECT {
            self.inspector
                .call_end(&mut self.data, inputs, ret.1, ret.0, ret.2)
        } else {
            ret
        }
    }
}
