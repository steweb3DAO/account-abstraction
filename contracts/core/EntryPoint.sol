/**
 ** Account-Abstraction (EIP-4337) singleton EntryPoint implementation.
 ** Only one instance required on each chain.
 **/
// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */

import "../interfaces/IAccount.sol";
import "../interfaces/IPaymaster.sol";

import "../interfaces/IAggregatedAccount.sol";
import "../interfaces/IEntryPoint.sol";
import "./StakeManager.sol";
import "./SenderCreator.sol";
import "hardhat/console.sol";

contract EntryPoint is IEntryPoint, StakeManager {
    using UserOperationLib for UserOperation;

    SenderCreator private immutable senderCreator = new SenderCreator();

    // internal value used during simulation: need to query aggregator.
    address private constant SIMULATE_FIND_AGGREGATOR = address(1);

    /**
     * for simulation purposes, validateUserOp (and validatePaymasterUserOp) must return this value
     * in case of signature failure, instead of revert.
     */
    uint256 public constant SIG_VALIDATION_FAILED = 1;

    /**
     * compensate the caller's beneficiary address with the collected fees of all UserOperations.
     * @param beneficiary the address to receive the fees
     * @param amount amount to transfer.
     */
    function _compensate(address payable beneficiary, uint256 amount) internal {
        require(beneficiary != address(0), "AA90 invalid beneficiary");
        (bool success, ) = beneficiary.call{value: amount}("");
        require(success, "AA91 failed send to beneficiary");
    }

    /**
     * execute a user op
     * @param opIndex into into the opInfo array
     * @param userOp the userOp to execute
     * @param opInfo the opInfo filled by validatePrepayment for this userOp.
     * @return collected the total amount this userOp paid.
     */
    function _executeUserOp(
        uint256 opIndex,
        UserOperation calldata userOp,
        UserOpInfo memory opInfo
    ) private returns (uint256 collected) {
        uint256 preGas = gasleft();
        bytes memory context = getMemoryBytesFromOffset(opInfo.contextOffset);

        // try catch语法，在抛出异常时，运行指定逻辑
        // innerHandleOp 内部也会统计preOpGas等，并且调用 _handlePostOp
        try this.innerHandleOp(userOp.callData, opInfo, context) returns (
            uint256 _actualGasCost
        ) {
            collected = _actualGasCost;
        } catch {
            // 运行前的gas余额 - 当前的gas余额 + 前置paymaster校验环节的gas，在这里一次性统计出来，在后面补偿
            uint256 actualGas = preGas - gasleft() + opInfo.preOpGas;
            // 如果op执行失败，则执行cath逻辑，同时更新状态为postOpReverted
            collected = _handlePostOp(
                opIndex,
                IPaymaster.PostOpMode.postOpReverted,
                opInfo,
                context,
                actualGas
            );
        }
    }

    /**
     * Execute a batch of UserOperation.
     * no signature aggregator is used.
     * if any account requires an aggregator (that is, it returned an "actualAggregator" when
     * performing simulateValidation), then handleAggregatedOps() must be used instead.
     * @param ops the operations to execute
     * @param beneficiary the address to receive the fees
     */

    // 这个是没有权限控制的，任何人都可以调用吗？ 是的，具体流程是：
    // 任何人 -> entryPoint.handleOps(userOps) -> userOps[i].sender.call(userOps[i].calldata)
    // 即：任何人都可以调用handleOps，这个函数内部会调用account的最终执行逻辑
    function handleOps(
        UserOperation[] calldata ops,
        address payable beneficiary
    ) public {
        console.log("hello world!");
        uint256 opslen = ops.length;
        // 注意这里是另外一个结构数组，里面的数据是内存数据
        // 因为在handleOps阶段，用户的签名已经校验过了，这里只负责执行
        UserOpInfo[] memory opInfos = new UserOpInfo[](opslen);

        unchecked {
            for (uint256 i = 0; i < opslen; i++) {
                // opInfo是空的，在下面的 _validatePrepayment 中完成复制，并且数据已经复制到opInfo中
                UserOpInfo memory opInfo = opInfos[i];
                (
                    uint256 deadline,
                    uint256 paymasterDeadline,

                ) = _validatePrepayment(i, ops[i], opInfo, address(0));
                _validateDeadline(i, opInfo, deadline, paymasterDeadline);
            }

            // 消耗的手续费，最终需要用户补偿
            uint256 collected = 0;

            for (uint256 i = 0; i < opslen; i++) {
                // calldata依然从原始的ops中获取
                // opInfos中已经被赋值了（已经使用demo验证过了）
                collected += _executeUserOp(i, ops[i], opInfos[i]);
            }

            _compensate(beneficiary, collected);
        } //unchecked
    }

    // UserOps handled, per aggregator
    // 每一组UserOps分配给了一个Aggregator，这个结构里面存储了所有的元素
    /*
    struct UserOpsPerAggregator {
        UserOperation[] userOps;

        // aggregator address
        IAggregator aggregator;
        // aggregated signature
        bytes signature;
    }
    */

    /**
     * Execute a batch of UserOperation with Aggregators
     * @param opsPerAggregator the operations to execute, grouped by aggregator (or address(0) for no-aggregator accounts)
     * @param beneficiary the address to receive the fees
     */
    function handleAggregatedOps(
        UserOpsPerAggregator[] calldata opsPerAggregator,
        address payable beneficiary
    ) public {
        uint256 opasLen = opsPerAggregator.length;
        uint256 totalOps = 0;
        for (uint256 i = 0; i < opasLen; i++) {
            totalOps += opsPerAggregator[i].userOps.length;
        }

        UserOpInfo[] memory opInfos = new UserOpInfo[](totalOps);

        uint256 opIndex = 0;
        for (uint256 a = 0; a < opasLen; a++) {
            UserOpsPerAggregator calldata opa = opsPerAggregator[a];
            UserOperation[] calldata ops = opa.userOps;
            IAggregator aggregator = opa.aggregator;
            uint256 opslen = ops.length;
            for (uint256 i = 0; i < opslen; i++) {
                UserOpInfo memory opInfo = opInfos[opIndex];
                (
                    uint256 deadline,
                    uint256 paymasterDeadline,

                ) = _validatePrepayment(
                        opIndex,
                        ops[i],
                        opInfo,
                        address(aggregator)
                    );
                _validateDeadline(i, opInfo, deadline, paymasterDeadline);
                opIndex++;
            }

            if (address(aggregator) != address(0)) {
                // solhint-disable-next-line no-empty-blocks
                try aggregator.validateSignatures(ops, opa.signature) {} catch {
                    revert SignatureValidationFailed(address(aggregator));
                }
            }
        }

        uint256 collected = 0;
        opIndex = 0;
        for (uint256 a = 0; a < opasLen; a++) {
            UserOpsPerAggregator calldata opa = opsPerAggregator[a];
            emit SignatureAggregatorChanged(address(opa.aggregator));
            UserOperation[] calldata ops = opa.userOps;
            uint256 opslen = ops.length;

            for (uint256 i = 0; i < opslen; i++) {
                collected += _executeUserOp(opIndex, ops[i], opInfos[opIndex]);
                opIndex++;
            }
        }
        emit SignatureAggregatorChanged(address(0));

        _compensate(beneficiary, collected);
    }

    /// 这个是给链下程序调用的
    function simulateHandleOp(UserOperation calldata op) external override {
        UserOpInfo memory opInfo;

        (uint256 deadline, uint256 paymasterDeadline, ) = _validatePrepayment(
            0,
            op,
            opInfo,
            SIMULATE_FIND_AGGREGATOR
        );
        //ignore signature check failure
        if (deadline == SIG_VALIDATION_FAILED) {
            deadline = 0;
        }
        if (paymasterDeadline == SIG_VALIDATION_FAILED) {
            paymasterDeadline = 0;
        }
        _validateDeadline(0, opInfo, deadline, paymasterDeadline);
        numberMarker();
        uint256 paid = _executeUserOp(0, op, opInfo);
        revert ExecutionResult(
            opInfo.preOpGas,
            paid,
            deadline,
            paymasterDeadline
        );
    }

    //a memory copy of UserOp fields (except that dynamic byte arrays: callData, initCode and signature
    //   struct UserOperation {

    //     address sender;
    //     uint256 nonce;
    //     /// bytes initCode;
    //     /// bytes callData;
    //     uint256 callGasLimit;
    //     uint256 verificationGasLimit;
    //     uint256 preVerificationGas;
    //     uint256 maxFeePerGas;
    //     uint256 maxPriorityFeePerGas;
    // .   paymaster <- 新增的
    //     /// bytes paymasterAndData;
    //     /// bytes signature;
    // }

    struct MemoryUserOp {
        address sender;
        uint256 nonce;
        uint256 callGasLimit;
        uint256 verificationGasLimit;
        uint256 preVerificationGas;
        address paymaster;
        uint256 maxFeePerGas;
        uint256 maxPriorityFeePerGas;
    }

    // 注意区分这两个结构:
    // struct UserOperation, 这个是用户需要执行的操作，是标准的结构
    // struct UserOpInfo, 这个是程序运行中定义的结构，里面有个MemoryUserOp，字段与UserOperation很相似，（缺少动态数据：initCode，calldata，signature等，上面有介绍）
    struct UserOpInfo {
        MemoryUserOp mUserOp;
        bytes32 userOpHash;
        uint256 prefund;
        uint256 contextOffset;
        uint256 preOpGas;
    }

    /**
     * inner function to handle a UserOperation.
     * Must be declared "external" to open a call context, but it can only be called by handleOps.
     */
    function innerHandleOp(
        bytes calldata callData,
        UserOpInfo memory opInfo,
        bytes calldata context
    ) external returns (uint256 actualGasCost) {
        uint256 preGas = gasleft();
        // 权宜之计，既不想让外部调用，又想传递context进来，所以加上下面的require限制
        require(msg.sender == address(this), "AA92 internal call only");
        MemoryUserOp memory mUserOp = opInfo.mUserOp;

        // 一共三种状态，默认是成功的
        IPaymaster.PostOpMode mode = IPaymaster.PostOpMode.opSucceeded;

        // callData里面是account调用execute方法的细节，内部包含用户具体想执行的业务（如用户想调用uniswap的swap方法）
        // function execute(address dest, uint256 value, bytes calldata func) external {
        if (callData.length > 0) {
            // 这里是最终调用user的account，执行exec函数，具体细节在callData中
            (bool success, bytes memory result) = address(mUserOp.sender).call{
                gas: mUserOp.callGasLimit
            }(callData);
            if (!success) {
                if (result.length > 0) {
                    emit UserOperationRevertReason(
                        opInfo.userOpHash,
                        mUserOp.sender,
                        mUserOp.nonce,
                        result
                    );
                }
                // 调用失败，更新状态mode
                mode = IPaymaster.PostOpMode.opReverted;
            }
        }

        // 没看到revert，可能是哪些情况导致失败呢(gas不足等）？？ // TODO duke
        unchecked {
            uint256 actualGas = preGas - gasleft() + opInfo.preOpGas;
            //note: opIndex is ignored (relevant only if mode==postOpReverted, which is only possible outside of innerHandleOp)
            return _handlePostOp(0, mode, opInfo, context, actualGas);
        }
    }

    /**
     * generate a request Id - unique identifier for this request.
     * the request ID is a hash over the content of the userOp (except the signature), the entrypoint and the chainid.
     */
    function getUserOpHash(UserOperation calldata userOp)
        public
        view
        returns (bytes32)
    {
        return
            keccak256(abi.encode(userOp.hash(), address(this), block.chainid));
    }

    /**
     * copy general fields from userOp into the memory opInfo structure.
     */
    function _copyUserOpToMemory(
        UserOperation calldata userOp,
        MemoryUserOp memory mUserOp
    ) internal pure {
        mUserOp.sender = userOp.sender;
        mUserOp.nonce = userOp.nonce;
        mUserOp.callGasLimit = userOp.callGasLimit;
        mUserOp.verificationGasLimit = userOp.verificationGasLimit;
        mUserOp.preVerificationGas = userOp.preVerificationGas;
        mUserOp.maxFeePerGas = userOp.maxFeePerGas;
        mUserOp.maxPriorityFeePerGas = userOp.maxPriorityFeePerGas;
        bytes calldata paymasterAndData = userOp.paymasterAndData;
        if (paymasterAndData.length > 0) {
            require(
                paymasterAndData.length >= 20,
                "AA93 invalid paymasterAndData"
            );
            mUserOp.paymaster = address(bytes20(paymasterAndData[:20]));
        } else {
            mUserOp.paymaster = address(0);
        }
    }

    /**
     * Simulate a call to account.validateUserOp and paymaster.validatePaymasterUserOp.
     * @dev this method always revert. Successful result is ValidationResult error. other errors are failures.
     * @dev The node must also verify it doesn't use banned opcodes, and that it doesn't reference storage outside the account's data.
     * @param userOp the user operation to validate.
     */
    function simulateValidation(UserOperation calldata userOp) external {
        UserOpInfo memory outOpInfo;

        (
            uint256 deadline,
            uint256 paymasterDeadline,
            address aggregator
        ) = _validatePrepayment(0, userOp, outOpInfo, SIMULATE_FIND_AGGREGATOR);
        StakeInfo memory paymasterInfo = getStakeInfo(
            outOpInfo.mUserOp.paymaster
        );
        StakeInfo memory senderInfo = getStakeInfo(outOpInfo.mUserOp.sender);
        bytes calldata initCode = userOp.initCode;
        address factory = initCode.length >= 20
            ? address(bytes20(initCode[0:20]))
            : address(0);
        StakeInfo memory factoryInfo = getStakeInfo(factory);

        ReturnInfo memory returnInfo = ReturnInfo(
            outOpInfo.preOpGas,
            outOpInfo.prefund,
            deadline,
            paymasterDeadline,
            getMemoryBytesFromOffset(outOpInfo.contextOffset)
        );

        if (aggregator != address(0)) {
            AggregatorStakeInfo memory aggregatorInfo = AggregatorStakeInfo(
                aggregator,
                getStakeInfo(aggregator)
            );
            revert ValidationResultWithAggregation(
                returnInfo,
                senderInfo,
                factoryInfo,
                paymasterInfo,
                aggregatorInfo
            );
        }
        revert ValidationResult(
            returnInfo,
            senderInfo,
            factoryInfo,
            paymasterInfo
        );
    }

    function _getRequiredPrefund(MemoryUserOp memory mUserOp)
        internal
        view
        returns (uint256 requiredPrefund)
    {
        unchecked {
            //when using a Paymaster, the verificationGasLimit is used also to as a limit for the postOp call.
            // our security model might call postOp eventually twice
            uint256 mul = mUserOp.paymaster != address(0) ? 3 : 1;
            uint256 requiredGas = mUserOp.callGasLimit +
                mUserOp.verificationGasLimit *
                mul +
                mUserOp.preVerificationGas;

            // TODO: copy logic of gasPrice?
            requiredPrefund = requiredGas * getUserOpGasPrice(mUserOp);
        }
    }

    // create the sender's contract if needed.
    // 如果sender的合约不存在，则需要创建，并且创建之后得到的地址要与sender相同
    function _createSenderIfNeeded(
        uint256 opIndex,
        UserOpInfo memory opInfo,
        bytes calldata initCode
    ) internal {
        if (initCode.length != 0) {
            address sender = opInfo.mUserOp.sender;

            // 这个sender是随着op一起传递过来的，地址是链下计算的，最初链上是没有合约与之对应的，我们这段代码就是为了创建其链上合约
            // 所以在此处，sender的code必须为零，否则不需要进入这段逻辑
            if (sender.code.length != 0)
                revert FailedOp(
                    opIndex,
                    address(0),
                    "AA10 sender already constructed"
                );

            // 这里使用了最初的状态变量senderCreator，其内部会提供一个创建account的方法，里面调用的是factory合约调用calldata方式，使用assembly汇编call方式
            address sender1 = senderCreator.createSender{
                gas: opInfo.mUserOp.verificationGasLimit
            }(initCode);
            // 这里三个if条件确保创建的sender与代码匹配
            if (sender1 == address(0))
                revert FailedOp(
                    opIndex,
                    address(0),
                    "AA13 initCode failed or OOG"
                );
            if (sender1 != sender)
                revert FailedOp(
                    opIndex,
                    address(0),
                    "AA14 initCode must return sender"
                );
            if (sender1.code.length == 0)
                revert FailedOp(
                    opIndex,
                    address(0),
                    "AA15 initCode must create sender"
                );

            address factory = address(bytes20(initCode[0:20]));
            emit AccountDeployed(
                opInfo.userOpHash,
                sender,
                factory,
                opInfo.mUserOp.paymaster
            );
        }
    }

    /**
     * Get counterfactual sender address.
     *  Calculate the sender contract address that will be generated by the initCode and salt in the UserOperation.
     * this method always revert, and returns the address in SenderAddressResult error
     * @param initCode the constructor code to be passed into the UserOperation.
     */
    function getSenderAddress(bytes calldata initCode) public {
        revert SenderAddressResult(senderCreator.createSender(initCode));
    }

    /**
     * call account.validateUserOp.
     * revert (with FailedOp) in case validateUserOp reverts, or account didn't send required prefund.
     * decrement account's deposit if needed
     */
    /*
    from
    to
    value
    gaslimit: 100000000
    */
    function _validateAccountPrepayment(
        uint256 opIndex,
        UserOperation calldata op,
        UserOpInfo memory opInfo,
        address aggregator,
        uint256 requiredPrefund
    )
        internal
        returns (
            uint256 gasUsedByValidateAccountPrepayment,
            address actualAggregator,
            uint256 deadline
        )
    {
        unchecked {
            uint256 preGas = gasleft();
            MemoryUserOp memory mUserOp = opInfo.mUserOp;
            address sender = mUserOp.sender;

            // 这里是创建account的逻辑
            _createSenderIfNeeded(opIndex, opInfo, op.initCode);

            // address private constant SIMULATE_FIND_AGGREGATOR = address(1);
            // 链下模拟函数会执行这里，真正链上执行时跳过这段逻辑
            if (aggregator == SIMULATE_FIND_AGGREGATOR) {
                numberMarker();

                if (sender.code.length == 0) {
                    // it would revert anyway. but give a meaningful message
                    revert FailedOp(0, address(0), "AA20 account not deployed");
                }
                if (
                    mUserOp.paymaster != address(0) &&
                    mUserOp.paymaster.code.length == 0
                ) {
                    // it would revert anyway. but give a meaningful message
                    revert FailedOp(
                        0,
                        address(0),
                        "AA30 paymaster not deployed"
                    );
                }
                // during simulation, we don't use given aggregator,
                // but query the account for its aggregator
                try IAggregatedAccount(sender).getAggregator() returns (
                    address userOpAggregator
                ) {
                    aggregator = actualAggregator = userOpAggregator;
                } catch {
                    aggregator = actualAggregator = address(0);
                }
            }
            // requiredPrefund : 100
            // bal: 80
            // missingAccountFunds: 20
            uint256 missingAccountFunds = 0;
            address paymaster = mUserOp.paymaster;
            if (paymaster == address(0)) {
                // paymaster为0，说明没有指定paymaster，需要account自己支付，没有垫付
                // 这里的balanceOf是stakeManager中的deposit值
                // 说明：在没有指定paymaster时，会优先使用sender存储在stakeManager中的eth支付gas
                // 如果这部分不足，则会使用sender链上账户的资金
                uint256 bal = balanceOf(sender);
                missingAccountFunds = bal > requiredPrefund
                    ? 0
                    : requiredPrefund - bal;
            }
            // 这个Account在ValidateUserOp的时候会向entrypoint转入eth，并且更新deposits，所以在下面会扣掉 必要的gasfee，重新更新deposit
            // 如果用户没有指定paymaster，则missingAccountFunds一定会自己支付，在执行validateUserOp也会传入非零的值，如果eth不足，会revert
            // 如果用户已经指定paymaster，则missingAccountFunds会传入0，所以在执行call转账时，会转入0，即使自己账户余额为0，也不会revert
            try
                IAccount(sender).validateUserOp{
                    gas: mUserOp.verificationGasLimit
                }(op, opInfo.userOpHash, aggregator, missingAccountFunds)
            returns (uint256 _deadline) {
                deadline = _deadline;
            } catch Error(string memory revertReason) {
                revert FailedOp(opIndex, address(0), revertReason);
            } catch {
                revert FailedOp(opIndex, address(0), "AA23 reverted (or OOG)");
            }
            // 如果用户没有指定paymaster
            if (paymaster == address(0)) {
                // 这里是查看这个用户的质押情况，里面主要是两个字段：deposit，stake，第一个是存入的eth，第二个是stake的eth（可以设置unstake seconds）
                // 与上面的balanceOf配合使用，减掉
                // 上面执行IAccount(sender).validateUserOp时，内部调用call方法转入eth，然后在entrypoint层面会调用父合约StakeManager中的receive->depositTo，从而更新了deposit字段
                // 所以此处的deposit一定是大于requiredPrefund的
                DepositInfo storage senderInfo = deposits[sender];
                uint256 deposit = senderInfo.deposit;
                if (requiredPrefund > deposit) {
                    revert FailedOp(
                        opIndex,
                        address(0),
                        "AA21 didn't pay prefund"
                    );
                }
                senderInfo.deposit = uint112(deposit - requiredPrefund);
            }
            gasUsedByValidateAccountPrepayment = preGas - gasleft();
        }
    }

    /**
     * in case the request has a paymaster:
     * validate paymaster is staked and has enough deposit.
     * call paymaster.validatePaymasterUserOp.
     * revert with proper FailedOp in case paymaster reverts.
     * decrement paymaster's deposit
     */
    function _validatePaymasterPrepayment(
        uint256 opIndex,
        UserOperation calldata op,
        UserOpInfo memory opInfo,
        uint256 requiredPreFund,
        uint256 gasUsedByValidateAccountPrepayment
    ) internal returns (bytes memory context, uint256 deadline) {
        unchecked {
            MemoryUserOp memory mUserOp = opInfo.mUserOp;
            uint256 verificationGasLimit = mUserOp.verificationGasLimit;
            require(
                verificationGasLimit > gasUsedByValidateAccountPrepayment,
                "AA41 too little verificationGas"
            );
            uint256 gas = verificationGasLimit -
                gasUsedByValidateAccountPrepayment;

            address paymaster = mUserOp.paymaster;
            DepositInfo storage paymasterInfo = deposits[paymaster];
            // 先确保用户指定的paymaster在entrypoint中存款充足
            uint256 deposit = paymasterInfo.deposit;
            if (deposit < requiredPreFund) {
                revert FailedOp(
                    opIndex,
                    paymaster,
                    "AA31 paymaster deposit too low"
                );
            }
            paymasterInfo.deposit = uint112(deposit - requiredPreFund);
            try
                IPaymaster(paymaster).validatePaymasterUserOp{gas: gas}(
                    op,
                    opInfo.userOpHash,
                    requiredPreFund
                )
            returns (bytes memory _context, uint256 _deadline) {
                // context: value to send to a postOp duke
                context = _context;
                deadline = _deadline;
            } catch Error(string memory revertReason) {
                revert FailedOp(opIndex, paymaster, revertReason);
            } catch {
                revert FailedOp(opIndex, paymaster, "AA33 reverted (or OOG)");
            }
        }
    }

    /**
     * revert if either account deadline or paymaster deadline is expired
     */
    function _validateDeadline(
        uint256 opIndex,
        UserOpInfo memory opInfo,
        uint256 deadline,
        uint256 paymasterDeadline
    ) internal view {
        //we want to treat "zero" as "maxint", so we subtract one, ignoring underflow
        unchecked {
            // solhint-disable-next-line not-rely-on-time
            if (deadline != 0 && deadline < block.timestamp) {
                if (deadline == SIG_VALIDATION_FAILED) {
                    revert FailedOp(
                        opIndex,
                        address(0),
                        "AA24 signature error"
                    );
                } else {
                    revert FailedOp(opIndex, address(0), "AA22 expired");
                }
            }
            // solhint-disable-next-line not-rely-on-time
            if (paymasterDeadline != 0 && paymasterDeadline < block.timestamp) {
                address paymaster = opInfo.mUserOp.paymaster;
                if (paymasterDeadline == SIG_VALIDATION_FAILED) {
                    revert FailedOp(opIndex, paymaster, "AA34 signature error");
                } else {
                    revert FailedOp(
                        opIndex,
                        paymaster,
                        "AA32 paymaster expired"
                    );
                }
            }
        }
    }

    /**
     * validate account and paymaster (if defined).
     * also make sure total validation doesn't exceed verificationGasLimit
     * this method is called off-chain (simulateValidation()) and on-chain (from handleOps)
     * @param opIndex the index of this userOp into the "opInfos" array
     * @param userOp the userOp to validate
     */
    // 两个地方会调用这个函数：handleOp or handleAggregatedOps （链上调用），simulateValidation（链下调用）
    function _validatePrepayment(
        uint256 opIndex,
        UserOperation calldata userOp,
        UserOpInfo memory outOpInfo,
        address aggregator
    )
        private
        returns (
            uint256 deadline,
            uint256 paymasterDeadline,
            address actualAggregator
        )
    {
        uint256 preGas = gasleft();
        MemoryUserOp memory mUserOp = outOpInfo.mUserOp;
        _copyUserOpToMemory(userOp, mUserOp);

        // keccak256(abi.encode(userOp.hash(), address(this), block.chainid));
        outOpInfo.userOpHash = getUserOpHash(userOp);

        // validate all numeric values in userOp are well below 128 bit, so they can safely be added
        // and multiplied without causing overflow

        // 111000
        // 111010000
        // 这里不是为了统计，而是为了确保不溢出
        uint256 maxGasValues = mUserOp.preVerificationGas |
            mUserOp.verificationGasLimit |
            mUserOp.callGasLimit |
            userOp.maxFeePerGas |
            userOp.maxPriorityFeePerGas;
        require(maxGasValues <= type(uint120).max, "AA94 gas values overflow");

        uint256 gasUsedByValidateAccountPrepayment;

        // 统计具体需要多少gasfee
        uint256 requiredPreFund = _getRequiredPrefund(mUserOp);

        (
            gasUsedByValidateAccountPrepayment,
            actualAggregator,
            deadline
        ) = _validateAccountPrepayment(
            opIndex,
            userOp,
            outOpInfo,
            aggregator,
            requiredPreFund
        );
        //a "marker" where account opcode validation is done and paymaster opcode validation is about to start
        // (used only by off-chain simulateValidation)

        // 给simulation使用的
        numberMarker();

        // 指定paymaster的时候，account校验的时候不需要向entrypoint转钱，具体的费用在下面的逻辑中处理
        bytes memory context;
        if (mUserOp.paymaster != address(0)) {
            (context, paymasterDeadline) = _validatePaymasterPrepayment(
                opIndex,
                userOp,
                outOpInfo,
                requiredPreFund,
                gasUsedByValidateAccountPrepayment
            );
        }
        unchecked {
            uint256 gasUsed = preGas - gasleft();

            if (userOp.verificationGasLimit < gasUsed) {
                revert FailedOp(
                    opIndex,
                    mUserOp.paymaster,
                    "AA40 over verificationGasLimit"
                );
            }
            outOpInfo.prefund = requiredPreFund;
            // 默认是0，当paymaster不为0的时候，会进行offset
            // 这两个字段是定义在userOpInfo中的，会在executeOp中调用
            // context: abi.encode(account, token, gasPriceUserOp, maxTokenCost, maxCost),0);
            // 这里就是赋值，应该是gas节约
            outOpInfo.contextOffset = getOffsetOfMemoryBytes(context);
            outOpInfo.preOpGas = preGas - gasleft() + userOp.preVerificationGas;
        }
    }

    /**
     * process post-operation.
     * called just after the callData is executed.
     * if a paymaster is defined and its validation returned a non-empty context, its postOp is called.
     * the excess amount is refunded to the account (or paymaster - if it is was used in the request)
     * @param opIndex index in the batch
     * @param mode - whether is called from innerHandleOp, or outside (postOpReverted)
     * @param opInfo userOp fields and info collected during validation
     * @param context the context returned in validatePaymasterUserOp
     * @param actualGas the gas used so far by this user operation
     */
    function _handlePostOp(
        uint256 opIndex,
        IPaymaster.PostOpMode mode,
        UserOpInfo memory opInfo,
        bytes memory context,
        uint256 actualGas
    ) private returns (uint256 actualGasCost) {
        uint256 preGas = gasleft();
        unchecked {
            address refundAddress;
            MemoryUserOp memory mUserOp = opInfo.mUserOp;
            uint256 gasPrice = getUserOpGasPrice(mUserOp);

            address paymaster = mUserOp.paymaster;
            if (paymaster == address(0)) {
                refundAddress = mUserOp.sender;
            } else {
                refundAddress = paymaster;
                if (context.length > 0) {
                    actualGasCost = actualGas * gasPrice;
                    if (mode != IPaymaster.PostOpMode.postOpReverted) {
                        // 执行userOpertation失败的时候，会再次执行postOp，此时会进入这个分支
                        IPaymaster(paymaster).postOp{
                            gas: mUserOp.verificationGasLimit
                        }(mode, context, actualGasCost);
                    } else {
                        // solhint-disable-next-line no-empty-blocks
                        // 这两句postOp是完全一致的，只不过后者多了个catch，为了捕捉失败原因，上面那个状态是执行成功，或者失败
                        try
                            IPaymaster(paymaster).postOp{
                                gas: mUserOp.verificationGasLimit
                            }(mode, context, actualGasCost)
                        {} catch Error(string memory reason) {
                            revert FailedOp(opIndex, paymaster, reason);
                        } catch {
                            revert FailedOp(
                                opIndex,
                                paymaster,
                                "A50 postOp revert"
                            );
                        }
                    }
                }
            }
            actualGas += preGas - gasleft();
            actualGasCost = actualGas * gasPrice;
            if (opInfo.prefund < actualGasCost) {
                revert FailedOp(
                    opIndex,
                    paymaster,
                    "A51 prefund below actualGasCost"
                );
            }

            // 会把多余的gas返还给支付者（可能是account本身，也可能是paymaster）
            uint256 refund = opInfo.prefund - actualGasCost;
            internalIncrementDeposit(refundAddress, refund);
            bool success = mode == IPaymaster.PostOpMode.opSucceeded;
            emit UserOperationEvent(
                opInfo.userOpHash,
                mUserOp.sender,
                mUserOp.paymaster,
                mUserOp.nonce,
                success,
                actualGasCost,
                actualGas
            );
        } // unchecked
    }

    /**
     * the gas price this UserOp agrees to pay.
     * relayer/block builder might submit the TX with higher priorityFee, but the user should not
     */
    function getUserOpGasPrice(MemoryUserOp memory mUserOp)
        internal
        view
        returns (uint256)
    {
        unchecked {
            uint256 maxFeePerGas = mUserOp.maxFeePerGas;
            uint256 maxPriorityFeePerGas = mUserOp.maxPriorityFeePerGas;
            if (maxFeePerGas == maxPriorityFeePerGas) {
                //legacy mode (for networks that don't support basefee opcode)
                return maxFeePerGas;
            }

            // block.basefee // TODO duke
            return min(maxFeePerGas, maxPriorityFeePerGas + block.basefee);
        }
    }

    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    function getOffsetOfMemoryBytes(bytes memory data)
        internal
        pure
        returns (uint256 offset)
    {
        assembly {
            offset := data
        }
    }

    function getMemoryBytesFromOffset(uint256 offset)
        internal
        pure
        returns (bytes memory data)
    {
        assembly {
            data := offset
        }
    }

    //place the NUMBER opcode in the code.
    // this is used as a marker during simulation, as this OP is completely banned from the simulated code of the
    // account and paymaster.
    function numberMarker() internal view {
        // https://docs.soliditylang.org/en/latest/yul.html#yul duke
        // number(): current block number
        assembly {
            mstore(0, number())
        }
    }
}
