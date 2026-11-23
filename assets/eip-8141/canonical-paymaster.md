# Canonical paymaster reference artifacts

## Annotated assembly

Storage layout: `slot0 = released (high 96 bits) || signer (low 160 bits)`, `slot1 = pending_withdrawal_amount`,
`slot2 = pending_unlock_time`, `slot3 = pending_new_signer`. `DELAY = 86400`.
Jump targets are assembled as fixed-width `push2 <label>`; each label below is a
`jumpdest`. This listing assembles byte-for-byte to the runtime bytecode and code
hash further down.

```asm
;; ---- dispatch ---------------------------------------------------
    callvalue                       ; value carried?
    push2 has_value
    jumpi                           ;   -> deposit / reject
    calldatasize                    ; any calldata?
    push2 admin
    jumpi                           ;   -> admin op dispatch
;; ---- pay: shared payment gate, optional ticket check --------
pay:
    jumpdest
                                    ; else empty calldata + zero value = pay frame
;; ---- payment-validation gate (pay frame) ------------------------
    push1 0x01                      ; param = scheme
    push1 0x01                      ; signature index 1
    sigparam                        ; scheme(1)
    iszero                          ; scheme == ARBITRARY (0x0)?
    push2 fail
    jumpi                           ;   ARBITRARY -> revert
    push0                           ; param = resolved_signer
    push1 0x01
    sigparam                        ; resolved_signer(1)
    push0
    sload                           ; slot0 = signer
    push1 0x60
    shl
    push1 0x60
    shr
    eq
    iszero                          ; resolved_signer != signer?
    push2 fail
    jumpi                           ;   -> revert
    push1 0x02                      ; param = msg
    push1 0x01
    sigparam                        ; msg(1)
    push2 fail
    jumpi                           ;   non-empty msg -> revert
    calldatasize
    iszero
    push2 pay_ok
    jumpi
    push1 0x01
    calldataload
    push0
    sload
    push1 0xa0
    shr
    gt
    iszero
    push2 fail
    jumpi
pay_ok:
    jumpdest
    push1 0x01                      ; scope = APPROVE_PAYMENT (0x1)
    push0                           ; length = 0
    push0                           ; offset = 0
    approve                         ; APPROVE(PAYMENT); exits frame successfully
;; ---- has_value: deposit iff no calldata, else reject ------------
has_value:
    jumpdest
    calldatasize
    push2 fail
    jumpi                           ;   value + calldata -> revert (admin non-payable)
    stop                            ;   plain deposit accepted
;; ---- admin: dispatch on first calldata byte ---------------------
admin:
    jumpdest
    push0
    calldataload
    push1 0xf8
    shr                             ; op = calldata[0]
    dup1
    iszero
    push2 pay_op
    jumpi
    dup1
    push1 0x05
    eq
    push2 raise
    jumpi
    dup1
    push1 0x01
    eq
    push2 w_init
    jumpi                           ; op == 1 -> initiate withdrawal
    dup1
    push1 0x02
    eq
    push2 r_init
    jumpi                           ; op == 2 -> initiate rotation
    dup1
    push1 0x03
    eq
    push2 cancel
    jumpi                           ; op == 3 -> cancel
    push1 0x04
    eq
    push2 finalize
    jumpi                           ; op == 4 -> finalize
                                    ; fall through to fail on any other op
;; ---- fail: revert -----------------------------------------------
fail:
    jumpdest
    push0
    push0
    revert
;; ---- w_init: initiate withdrawal(amount = calldata[1:33]) -------
w_init:
    jumpdest
    pop                             ; drop dispatch op byte
    ;; authorized(): caller == signer, OR a signer-signed entry@1
    caller
    push0
    sload                           ; slot0
    push1 0x60
    shl
    push1 0x60
    shr
    eq
    push2 auth_ok_0
    jumpi                           ;   caller == signer -> authorized
    push1 0x01                      ; else signature route: scheme(1) != ARBITRARY
    push1 0x01
    sigparam
    iszero
    push2 fail
    jumpi
    push0                           ; resolved_signer(1) == signer
    push1 0x01
    sigparam
    push0
    sload
    push1 0x60
    shl
    push1 0x60
    shr
    eq
    iszero
    push2 fail
    jumpi
    push1 0x02                      ; msg(1) == 0
    push1 0x01
    sigparam
    push2 fail
    jumpi
auth_ok_0:
    jumpdest
    push1 0x02
    sload                           ; slot2
    push2 fail
    jumpi                           ;   action already pending -> revert
    push1 0x01
    calldataload                    ; amount = calldata[1:33]
    dup1
    iszero
    push2 fail
    jumpi                           ;   amount == 0 -> revert
    push1 0x01
    sstore                          ; slot1 = amount
    timestamp
    push3 0x015180                  ; DELAY = 86400
    add
    push1 0x02
    sstore                          ; slot2 = now + DELAY
    stop
;; ---- r_init: initiate rotation(new_signer = calldata[1:33]) -----
r_init:
    jumpdest
    pop
    caller                          ; authorized() (identical gate)
    push0
    sload
    push1 0x60
    shl
    push1 0x60
    shr
    eq
    push2 auth_ok_1
    jumpi
    push1 0x01
    push1 0x01
    sigparam
    iszero
    push2 fail
    jumpi
    push0
    push1 0x01
    sigparam
    push0
    sload
    push1 0x60
    shl
    push1 0x60
    shr
    eq
    iszero
    push2 fail
    jumpi
    push1 0x02
    push1 0x01
    sigparam
    push2 fail
    jumpi
auth_ok_1:
    jumpdest
    push1 0x02
    sload
    push2 fail
    jumpi                           ;   action already pending -> revert
    push1 0x01
    calldataload                    ; new_signer = calldata[1:33]
    dup1
    iszero
    push2 fail
    jumpi                           ;   new_signer == 0 -> revert
    dup1
    push1 0xa0
    shr
    push2 fail
    jumpi
    push1 0x03
    sstore                          ; slot3 = new_signer
    timestamp
    push3 0x015180                  ; DELAY = 86400
    add
    push1 0x02
    sstore                          ; slot2 = now + DELAY
    stop
;; ---- cancel: clear pending state --------------------------------
cancel:
    jumpdest
    pop
    caller                          ; authorized() (identical gate)
    push0
    sload
    push1 0x60
    shl
    push1 0x60
    shr
    eq
    push2 auth_ok_2
    jumpi
    push1 0x01
    push1 0x01
    sigparam
    iszero
    push2 fail
    jumpi
    push0
    push1 0x01
    sigparam
    push0
    sload
    push1 0x60
    shl
    push1 0x60
    shr
    eq
    iszero
    push2 fail
    jumpi
    push1 0x02
    push1 0x01
    sigparam
    push2 fail
    jumpi
auth_ok_2:
    jumpdest
    push0
    push1 0x01
    sstore                          ; slot1 = 0
    push0
    push1 0x02
    sstore                          ; slot2 = 0
    push0
    push1 0x03
    sstore                          ; slot3 = 0
    stop
;; ---- finalize: anyone, once matured -----------------------------
finalize:
    jumpdest
    push1 0x02
    sload                           ; slot2 = unlock time
    dup1
    iszero
    push2 fail
    jumpi                           ;   no pending action -> revert
    timestamp
    lt                              ; now < unlock?
    push2 fail
    jumpi                           ;   not matured -> revert
    push1 0x01
    sload                           ; slot1 = amount
    dup1
    iszero
    push2 f_rot
    jumpi                           ;   amount == 0 -> rotation branch
    ;; withdrawal: clear slots 1 and 2 before the value-bearing call
    push0
    push1 0x01
    sstore                          ; slot1 = 0
    push0
    push1 0x02
    sstore                          ; slot2 = 0
    push0                           ; retLength
    push0                           ; retOffset
    push0                           ; argsLength
    push0                           ; argsOffset
    dup5                            ; value = amount
    push0
    sload                           ; to = signer (slot0)
    push1 0x60
    shl
    push1 0x60
    shr
    gas                             ; gas
    call                            ; CALL(gas, signer, amount, 0, 0, 0, 0)
    iszero
    push2 fail
    jumpi                           ;   failed send -> revert
    stop
;; ---- f_rot: finalize rotation -----------------------------------
f_rot:
    jumpdest
    pop                             ; drop amount (== 0)
    push1 0x03
    sload                           ; slot3 = new signer
    push0
    sload
    push1 0xa0
    shr
    push1 0xa0
    shl
    or
    push0
    sstore                          ; slot0 = new signer
    push0
    push1 0x03
    sstore                          ; slot3 = 0
    push0
    push1 0x02
    sstore                          ; slot2 = 0
    stop
;; ---- pay_op: op 0x00, data = 0x00 || ticket (33 bytes) -------
pay_op:
    jumpdest
    pop
    calldatasize
    push1 0x21
    eq
    iszero
    push2 fail
    jumpi
    push2 pay
    jump
;; ---- raise: op 0x05, released = calldata[1:33], increase only
raise:
    jumpdest
    pop
    caller
    push0
    sload
    push1 0x60
    shl
    push1 0x60
    shr
    eq
    push2 auth_ok_3
    jumpi
    push1 0x01
    push1 0x01
    sigparam
    iszero
    push2 fail
    jumpi
    push0
    push1 0x01
    sigparam
    push0
    sload
    push1 0x60
    shl
    push1 0x60
    shr
    eq
    iszero
    push2 fail
    jumpi
    push1 0x02
    push1 0x01
    sigparam
    push2 fail
    jumpi
auth_ok_3:
    jumpdest
    push1 0x01
    calldataload
    dup1
    push1 0x60
    shr
    push2 fail
    jumpi
    dup1
    push0
    sload
    push1 0xa0
    shr
    lt
    iszero
    push2 fail
    jumpi
    push1 0xa0
    shl
    push0
    sload
    push1 0x60
    shl
    push1 0x60
    shr
    or
    push0
    sstore
    stop
```

## Assembled runtime bytecode (563 bytes)

```text
0x3461004a5736610051575b60016001b415610084575f6001b45f5460601b60601c14156100845760026001b4610084573615610044576001355f5460a01c1115610084575b60015f5faa5b3661008457005b5f3560f81c80156101c857806005146101d7578060011461008857806002146100db578060031461013657600414610179575b5f5ffd5b50335f5460601b60601c146100bd5760016001b415610084575f6001b45f5460601b60601c14156100845760026001b4610084575b60025461008457600135801561008457600155426201518001600255005b50335f5460601b60601c146101105760016001b415610084575f6001b45f5460601b60601c14156100845760026001b4610084575b600254610084576001358015610084578060a01c61008457600355426201518001600255005b50335f5460601b60601c1461016b5760016001b415610084575f6001b45f5460601b60601c14156100845760026001b4610084575b5f6001555f6002555f600355005b60025480156100845742106100845760015480156101af575f6001555f6002555f5f5f5f845f5460601b60601c5af11561008457005b506003545f5460a01c60a01b175f555f6003555f600255005b5036602114156100845761000a565b50335f5460601b60601c1461020c5760016001b415610084575f6001b45f5460601b60601c14156100845760026001b4610084575b6001358060601c61008457805f5460a01c10156100845760a01b5f5460601b60601c175f5500
```

## Per-fork `keccak256` code hash

```text
0x9ba61d8f9c407b55a09e03489d1199cdb58c5e4faa924bba7d468156c41cafa8
```

The annotated listing above is the reproducible source for both the runtime bytecode and this code hash: it assembles byte-for-byte to them.
