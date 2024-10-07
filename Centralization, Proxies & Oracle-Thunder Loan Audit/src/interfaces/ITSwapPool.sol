// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.20;

// q why are we only using the price of a pool token in weth?

interface ITSwapPool {
    function getPriceOfOnePoolTokenInWeth() external view returns (uint256);
}
