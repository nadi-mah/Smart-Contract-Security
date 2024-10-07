// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

// @audit-info/low the IThunderLoan contract should be implemented by the ThunderLoan contract!
// e if this info issue has been solved we would not face the parameter issues.
interface IThunderLoan {
    function repay(address token, uint256 amount) external;
}
