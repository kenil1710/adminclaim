# AdminClaim demo statements (Polygon)

This file exists only to drive the AdminClaim **demo** deployment through every outcome. Each section makes a statement about a real Polygon contract. Some numbers are deliberately different from the chain so that the demo can show each verdict. None of this is any protocol's documentation; records filed from this file name it as `github.com/kenil1710/adminclaim`.

## 1. Statement that matches

The Safe `0xeE071f4B516F69a1603dA393CdE8e76C40E5Be85` is a 6-of-11 multisig.

## 2. Statement the chain is weaker than

The Safe `0x87D93d9B2C672bf9c9642d853a8682546a5012B5` is a 3-of-3 multisig, and every change it makes waits for a 48-hour timelock.

## 3. Statement the chain is stronger than

The multisig `0xD97221065E826167A2cFE3307972c0D42200fDB4` needs only 1 of 3 signatures.

## 4. Statement about an immutable contract

The wrapped token contract `0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270` is immutable and has no admin keys.

## 5. Statement code cannot check with standard patterns

The bridged token contract `0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619` is immutable.

## 6. Statement that is hard to read

The signer set of `0x1840c4D81d2C50B603da5391b6A24c1cD62D0B56` has changed over time: early drafts mentioned two of three, a later proposal floated five of nine, and the figure most often quoted today is four out of eight, although some pages still repeat the older numbers.
