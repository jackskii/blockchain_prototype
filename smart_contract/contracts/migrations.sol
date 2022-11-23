// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

contract Faucet {
    address Owner;
    constructor () {
        Owner = msg.sender;
    }
    modifier onlyOwner {
        require(msg.sender == Owner, "Not Owner");
        _;
    }
}