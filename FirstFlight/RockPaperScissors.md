# RockPaperScissors_Audit_Report

## H-01.Attackers Replace Players, Causing Game Failure and Fund Loss

### Summary

The attacker can replace the user after the user joins the game but before the game starts, resulting in the user not only being unable to play the game but also suffering a loss of funds.



### Vulnerability Details

The vulnerability is located in the `joinGameWithEth()` function and the `joinGameWithToken` function of the ` RockPaperScissors.sol ` file.

```solidity
function joinGameWithEth(uint256 _gameId) external payable {
    ...
    game.playerB = msg.sender;
    ...
}

function joinGameWithToken(uint256 _gameId) external {
    ...
    game.playerB = msg.sender;
    ...
}
```

When a user A calls `createGameWithEth` or `createGameWithToken` to create a game, and user B joins the game by calling `joinGameWithEth` or `joinGameWithToken`, the game does not start immediately. At this point, if an attacker also calls `joinGameWithEth` or `joinGameWithToken` to join the game, the player B in this round of the game will be replaced by the attacker. However, the funds that user B spent to join this round of the game will be lost forever.



### Proof of Concept

#### Test Case

```solidity
function testLockFunds() public {
    // init attacker
    address attacker = makeAddr("attacker");
    vm.deal(attacker, 10 ether);
    vm.prank(address(game));
    token.mint(attacker, 10);

    // playerA create the games
    vm.startPrank(playerA);
    uint256 gameIdWithETH = game.createGameWithEth{value: 1 ether}(TOTAL_TURNS, TIMEOUT);
    token.approve(address(game), 1);
    uint256 gameIdWithToken = game.createGameWithToken(TOTAL_TURNS, TIMEOUT);
    vm.stopPrank();

    // playerB join the games
    vm.startPrank(playerB);
    game.joinGameWithEth{value: 1 ether}(gameIdWithETH);
    token.approve(address(game), 1);
    game.joinGameWithToken(gameIdWithToken);
    vm.stopPrank();

    // check the variables before the attack
    (
        address storedPlayerAWithETH,
        address storedPlayerBWithETH,
        , , , , , , , , , , , , ,
    ) = game.games(gameIdWithETH);
    assertEq(storedPlayerAWithETH, playerA);
    assertEq(storedPlayerBWithETH, playerB);
    assertEq(address(game).balance, 2 ether);

    (
        address storedPlayerAWithToken,
        address storedPlayerBWithToken,
        , , , , , , , , , , , , ,
    ) = game.games(gameIdWithETH);
    assertEq(storedPlayerAWithToken, playerA);
    assertEq(storedPlayerBWithToken, playerB);
    assertEq(token.balanceOf(address(game)), 2);

    // attacker join the games
    vm.startPrank(attacker);
    game.joinGameWithEth{value: 1 ether}(gameIdWithETH);
    token.approve(address(game), 1);
    game.joinGameWithToken(gameIdWithToken);
    vm.stopPrank();

    // check the variables after the attack
    (
        storedPlayerAWithETH,
        storedPlayerBWithETH,
        , , , , , , , , , , , , ,
    ) = game.games(gameIdWithETH);
    assertEq(storedPlayerAWithETH, playerA);
    assertEq(storedPlayerBWithETH, attacker);
    assertEq(address(game).balance, 3 ether);

    (
        storedPlayerAWithToken,
        storedPlayerBWithToken,
        , , , , , , , , , , , , ,
    ) = game.games(gameIdWithETH);
    assertEq(storedPlayerAWithToken, playerA);
    assertEq(storedPlayerBWithToken, attacker);
    assertEq(token.balanceOf(address(game)), 3);
}
```

#### Output

```bash
Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 7.79ms (1.24ms CPU time)

Ran 1 test suite in 128.56ms (7.79ms CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)
```

### Impact

The user will not only be unable to play the game, but will also suffer a loss of funds.



### Recommendation

Add a game state: Ready. Update the game status to this value after Player B joins the game.

```solidity
enum GameState {
    Created,
    Ready,// add
    Committed,
    Revealed,
    Finished,
    Cancelled
}

function joinGameWithEth(uint256 _gameId) external payable {
    Game storage game = games[_gameId];

    require(game.state == GameState.Created, "Game not open to join");
    require(game.playerA != msg.sender, "Cannot join your own game");
    require(block.timestamp <= game.joinDeadline, "Join deadline passed");
    require(msg.value == game.bet, "Bet amount must match creator's bet");
    
    game.state = GameState.Ready; // add
    game.playerB = msg.sender;
    emit PlayerJoined(_gameId, msg.sender);
}

function joinGameWithToken(uint256 _gameId) external {
    Game storage game = games[_gameId];

    require(game.state == GameState.Created, "Game not open to join");
    require(game.playerA != msg.sender, "Cannot join your own game");
    require(block.timestamp <= game.joinDeadline, "Join deadline passed");
    require(game.bet == 0, "This game requires ETH bet");
    require(winningToken.balanceOf(msg.sender) >= 1, "Must have winning token");

    game.state = GameState.Ready; // add
    // Transfer token to contract
    winningToken.transferFrom(msg.sender, address(this), 1);
    game.playerB = msg.sender;
    emit PlayerJoined(_gameId, msg.sender);
}
```


