# Consensus siever makeup block and check vote

commit: 193fd6d48bee98a3102661a1fac71763124d55db

When candidate block vote is failed, leader lost candidate transactions.
So, Change checking vote logic to two step.

According to the previous code.
- make block
if new block is complained block
elif there are candidate txs(can be verified)
    if last unconfirmed block exists.
        if the block is not empty block or was not made by me
            if vote success
                1. confirm the block
            else
                2. return
                    2-1 the block is not empty block
                    2-2 the block is empty block and it was not made by me
else (there is no candidate tx)
    if last unconfirmed block exists and the block is not empty block
        if vote success
            3. confirm the block
        else
            4. return
    else # last unconfirmed block doesn't exist or the block is empty block
        5. return
            5-1 last unconfirmed block doesn't exist
            5-2 last unconfirmed block is empty block and the block was not made me
                5-2-1 vote is success
                5-2-2 vote is not success
                    5-2-2-1 vote is not completely failed (waiting for vote from other Reps)
                    5-2-2-2 vote is completely failed
            5-3 last unconfirmed block is empty block and the block was made me
            (5-2 and 5-3 are one case that the block is empty block)


Move makeup block (return case)
- I don't know if candidate txs(can be verified) exist
if new block is not complained block
    if last unconfirmed block exists
        if last unconfirmed block is not empty block
            if vote is not success and not completely failed
                # waiting for vote from other Reps.
                2-1, 4
        elif the block was not made by me
            if vote is not success and not completely failed
                2-2, 5-2-2-1
- makeup block
- I known that candidate txs(can be verified) exist
if new block is not complained block
    if there is no candidate tx
        if last unconfirmed block doesn't exist
            5-1
        elif last unconfirmed block is empty block
            5-2-1, 5-2-2-2, 5-3

In Addition,
If vote has completely been failed, throw out the last unconfirmed block and make a new block.
