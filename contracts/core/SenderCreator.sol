// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

/**
 * helper contract for EntryPoint, to call userOp.initCode from a "neutral" address,
 * which is explicitly not the entryPoint itself.
 */
contract SenderCreator {
    /**
     * call the "initCode" factory to create and return the sender account address
     * @param initCode the initCode value from a UserOp. contains 20 bytes of factory address, followed by calldata
     * @return sender the returned address of the created account, or zero address on failure.
     */
    function createSender(bytes calldata initCode)
        external
        returns (address sender)
    {
        // initCode: factory's address + simpleaccount's bytecode
        // 这个initAddress是factory地址
        address initAddress = address(bytes20(initCode[0:20]));
        bytes memory initCallData = initCode[20:];
        bool success;
        /* solhint-disable no-inline-assembly */
        // 这句代码的意思是：调用simpleAcountFactory的方法创建一个simpleAccount
        /*
         solidity 的factory.call
         assembly {
            call
         }
        */
        assembly {
            success := call(
                gas(), // gaslimit
                initAddress, // factory地址
                0, // value
                add(initCallData, 0x20), // factory的参数offset
                mload(initCallData), //
                0, //返回值
                32 //返回值size
            )
            sender := mload(0)
        }
        if (!success) {
            sender = address(0);
        }
    }
}
