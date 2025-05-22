# HawkHigh_Audit_Report

## H-01.Incorrect wage distribution

### Summary

The incorrect calculation formula can lead to erroneous wage distribution, thereby causing financial losses.



### Vulnerability Details

The vulnerability is located in the ` graduateAndUpgrade() ` function of the ` LevelOne.sol ` file.

```solidity
function graduateAndUpgrade(address _levelTwo, bytes memory) public onlyPrincipal {
    ...
    uint256 payPerTeacher = (bursary * TEACHER_WAGE) / PRECISION;
    uint256 principalPay = (bursary * PRINCIPAL_WAGE) / PRECISION;
    ...
}
```

The two calculation logics in the code above actually compute the total salaries of the teachers and the principal. When it comes to the final distribution, the total amount needs to be divided by the number of people.



### Proof of Concept

#### Test Case

```solidity
function testPayWages() public {
    levelTwoImplementation = new LevelTwo();
    levelTwoImplementationAddress = address(levelTwoImplementation);
    bytes memory data = abi.encodeCall(LevelTwo.graduate, ());

    // add student
    _studentsEnrolled();

    address teacher_third = makeAddr("teacher_third");
    vm.startPrank(principal);
    // add teacher
    levelOneProxy.addTeacher(alice);
    levelOneProxy.addTeacher(bob);
    levelOneProxy.addTeacher(teacher_third);

    levelOneProxy.startSession(70);
    
    // total = 6 * 5000 ether
    // 35% = 10500 ether
    // 5% = 1500 ether
    // 2 teacher * 10500 < 30000
    // 3 teacher * 10500 > 30000
    vm.expectRevert(
        abi.encodeWithSignature(
            "ERC20InsufficientBalance(address,uint256,uint256)",
            levelOneProxy,
            9000 ether,
            10500 ether)
    );
    levelOneProxy.graduateAndUpgrade(levelTwoImplementationAddress, data);
    vm.stopPrank();
}
```

#### Output

```bash
Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 6.30ms (703.29µs CPU time)

Ran 1 test suite in 1.40s (6.30ms CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)
```

### Impact

Incorrect salary distribution, leading to financial losses.



### Recommendation

The calculated result needs to be divided by the number of people.

```solidity
function graduateAndUpgrade(address _levelTwo, bytes memory) public onlyPrincipal {
    ...
    // uint256 payPerTeacher = (bursary * TEACHER_WAGE) / PRECISION;
    uint256 payPerTeacher = (bursary * TEACHER_WAGE) / PRECISION / totalTeachers;
    uint256 principalPay = (bursary * PRINCIPAL_WAGE) / PRECISION;
    ...
}
```



## H-02.The ` graduateAndUpgrade ` function does not actually upgrade

### Summary

When a principal calls the ` graduateAndUpgrade ` function, the contract does not actually upgrade.



### Vulnerability Details

The vulnerability is located in the ` graduateAndUpgrade() ` function of the ` LevelOne.sol ` file.

```solidity
function graduateAndUpgrade(address _levelTwo, bytes memory) public onlyPrincipal {
    ...
    _authorizeUpgrade(_levelTwo);
    ...
}
function _authorizeUpgrade(address newImplementation) internal override onlyPrincipal {}
```

The ` _authorizeUpgrade() ` function merely authorizes the upgrade, but does not actually upgrade the implementation contract.



### Proof of Concept

#### Test Case

```solidity
function testNotRealUpgrade() public schoolInSession {
    bytes32 implementationSlot = bytes32(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc);

    // before upgrade
    bytes32 slotValue = vm.load(address(levelOneProxy), implementationSlot);
    address implementationAddress = address(uint160(uint256(slotValue)));
    assertEq(implementationAddress, address(levelOneImplementationAddress));

    // upgrade
    levelTwoImplementation = new LevelTwo();
    levelTwoImplementationAddress = address(levelTwoImplementation);
    bytes memory data = abi.encodeCall(LevelTwo.graduate, ());
    vm.prank(principal);
    levelOneProxy.graduateAndUpgrade(levelTwoImplementationAddress, data);
    LevelTwo levelTwoProxy = LevelTwo(proxyAddress);

    // after upgrade
    slotValue = vm.load(address(levelTwoProxy), implementationSlot);
    implementationAddress = address(uint160(uint256(slotValue)));
    assertNotEq(implementationAddress, address(levelTwoImplementationAddress));
    // the same address as before
    assertEq(implementationAddress, address(levelOneImplementationAddress));
}
```

#### Output

```bash
Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 7.75ms (2.02ms CPU time)

Ran 1 test suite in 1.34s (7.75ms CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)
```

### Impact

Contract does not actually upgrade.



### Recommendation

Directly use the ` upgradeToAndCall() ` function from OpenZeppelin.

```solidity
// function graduateAndUpgrade(address _levelTwo, bytes memory) public onlyPrincipal {
function graduateAndUpgrade(address _levelTwo, bytes memory data) public onlyPrincipal {
    ...
    // _authorizeUpgrade(_levelTwo);
    upgradeToAndCall(_levelTwo, data);
    ...
}
function _authorizeUpgrade(address newImplementation) internal override onlyPrincipal {}
```

Of course, the `LevelTwo.sol` file also needs to be modified slightly.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

// add
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

// contract LevelTwo is Initializable {
contract LevelTwo is Initializable, UUPSUpgradeable {
    // add
    modifier onlyPrincipal() {
        if (msg.sender != principal) {
            revert HH__NotPrincipal();
        }
        _;
    }
    // add
    function _authorizeUpgrade(address newImplementation) internal override onlyPrincipal {}
}

```



## L-01.The principal can upgrade at will

### Summary

Due to the lack of checks, the principal can upgrade at will.



### Vulnerability Details

The vulnerability is located in the ` graduateAndUpgrade() ` function of the ` LevelOne.sol ` file.

The following is the description of the contract:

> Students must have gotten all reviews before system upgrade. System upgrade should not occur if any student has not gotten 4 reviews (one for each week);
>
> Any student who doesn't meet the `cutOffScore` should not be upgraded;
>
> System upgrade cannot take place unless school's `sessionEnd` has reached;

Students must receive four reviews and all of them must meet the `cutOffScore` before the system can be upgraded. However, the `principal` can call this function at will.



### Impact

This can lead to the principal violating the rules.



### Recommendation

Add some necessary check logic.

```solidity
function graduateAndUpgrade(address _levelTwo, bytes memory) public onlyPrincipal {
    if (_levelTwo == address(0)) {
        revert HH__ZeroAddress();
    }
    // add
    require(block.timestamp > sessionEnd + reviewTime, "Still within the session time");
    uint256 totalStudents = listOfStudents.length;
    for (uint256 n = 0; n < totalStudents; n++) {
        require(reviewCount[listOfStudents[n]] == 4, "Not having received all the reviews");
        require(studentScore[listOfStudents[n]] >= cutOffScore, "Some students have not passed");
    }
    ...
}
```







