// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "./UserOperation.sol";

/**
 * Aggregated Signatures validator.
 * 一堆验签
 */
interface IAggregator {
    /**
     * 验签一堆用户操作
     * validate aggregated signature.
     * revert if the aggregated signature does not match the given list of operations.
     * 验证聚合签名。
     * 如果聚合签名与给定的操作列表不匹配，则恢复。是不是把 userOps 里面的内容直接用私钥做了签名？然后这里做验签
     */
    function validateSignatures(
        UserOperation[] calldata userOps,
        bytes calldata signature
    ) external view;

    /**
     * 验证一个用户操作
     * validate signature of a single userOp
     * This method is should be called by bundler after EntryPoint.simulateValidation() returns (reverts) with ValidationResultWithAggregation
     * First it validates the signature over the userOp. then it return data to be used when creating the handleOps:
     * @param userOp the userOperation received from the user.
     * @return sigForUserOp the value to put into the signature field of the userOp when calling handleOps.
     *    (usually empty, unless account and aggregator support some kind of "multisig"
     * 验证单个 userOp 的签名
     * 这个方法应该在 EntryPoint.simulateValidation() 和 ValidationResultWithAggregation 返回后由 Bundler 调用
     * 首先验证 userOp 上的签名。然后返回创建 handleOps 时使用的数据
     * @param userOp the userOperation received from the user.
     * @return sigForUserOp 返回调用 handleOps 时放入 userOp 签名字段的值。
     * (通常为空，除非帐户和聚合器支持某种“multisig”）
     */
    function validateUserOpSignature(
        UserOperation calldata userOp
    ) external view returns (bytes memory sigForUserOp);

    /**
     * TODO off-chain 和 validateSignatures 区别是什么？
     * aggregate multiple signatures into a single value.
     * This method is called off-chain to calculate the signature to pass with handleOps()
     * bundler MAY use optimized custom code perform this aggregation
     * @param userOps array of UserOperations to collect the signatures from.
     * @return aggregatesSignature the aggregated signature
     */
    function aggregateSignatures(
        UserOperation[] calldata userOps
    ) external view returns (bytes memory aggregatesSignature);
}
