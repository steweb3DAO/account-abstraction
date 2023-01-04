// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "./UserOperation.sol";
import "./IAccount.sol";
import "./IAggregator.sol";

/**
 * Aggregated account, that support IAggregator.
 * - the validateUserOp will be called only after the aggregator validated this account (with all other accounts of this aggregator).
 * - 只有在聚合器验证该帐户(以及该聚合器的所有其他帐户)之后，才会调用 validateUserOp。
 * - the validateUserOp MUST valiate the aggregator parameter, and MAY ignore the userOp.signature field.
 * - validateUserOp 必须验证 aggregator 参数，可以忽略userOp。签名字段。
 */
interface IAggregatedAccount is IAccount {
    /**
     * return the address of the signature aggregator the account supports.
     */
    function getAggregator() external view returns (address);
}
