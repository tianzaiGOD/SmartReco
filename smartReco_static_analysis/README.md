# Program List
- **code**: Source code of SmartReco static analysis module
    - **lib**
        - **onchain_tool.py**: Contains functions for fetch and hanle onchain data
    - **analysis_slither.py**: Use slither to analysis the source code of contract, and provide some useful information, like DFG
    - **collect_dapp_information.py**: Handle contracts of dapps in **./dataset**, collect creator-dapp dataset
    - **execute_with_transaction.py**: Responsible for invoking the SmartReco dynamic analysis module, such as replay and validation.
    - **generate_tx_with_abi.py**: Responsible for generating the input needed for the execution function.
    - **smartReco.py**: The entry point of SmartReco
- **record_data**: After running, SmartReco will generate this folder to store the results and cache some contextual data
    - **cache**: SmartReco caches data that fetchs from Etherscan and RPC requests and stores here
    - **err_info(optional)**: If SmartReco executes unsuccessful, the error will store here
    - **verify**: All analysis results store here
        - **0x123123123**: All the detection results for this contract are stored in this folder.
            - **unknown**: If SmartReco detects a builder that is not present in the current dataset during analysis, it will record the address of the contract for you to manually inspect.
            - **0x123123123**: The replay result is store as

                `Final Result | Execution Result of SmartReco | Origin Result| Transaction Hash`
            - **0x123123123_args**: If SmartReco find a ROR, it will store the arguments to *smartReco_dynamic_analysis* here, or you won't find this file. The first argument indicates how the arguments are generated.
                - **origin**: the origin transaction
                - **payable**: through mutate *value*
                - **random**: through mutate *input*
                - **without_input**: througn randomly generate
            - **0x123123123_implicit_tx**: If SmartReco find a ROR, it will store the entry function transaction here, or you won't find this file.
            - **0x123123123_result**: If SmartReco find a ROR, the detection report will store here, or you won't find this file.
