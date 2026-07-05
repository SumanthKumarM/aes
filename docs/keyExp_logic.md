### Working of KeyExpansion logic in rtl:
For Nk=6, we have 13 rounds in total where addRoundKey is used right. now key expansion always gives us 6 expanded words ({w0,w1,w2,w3,w4,w5}) at a time but addRoundKey always consumes 4 words per round. So according to that, words consumed by addRoundKey based on round number would be:
```
round-0: {w0, w1, w2, w3}
round-1: {prev(w4, w5), w0, w1} 
round-2: prev{w2, w3, w4, w5}
round-3: prev{w0, w1, w2, w3} 
round-4: {prev(w4, w5), w0, w1}
.
.
.
```

So from above interpretation the indices don't cross the range 0-5. Why? because there are exactly 6 expanded words in AES-192. 

### Now how did I map those?
this is the rtl i wrote for key expansion for AES-192;
```sv
2'b10: begin  // AES-192
    if(concatenate_sel(round_num) == 2'b11) begin  // these rounds don't require new expanded KEYs, previous batch KEYs are enough
        // disabling Sbox as it's not required for these rounds
        sbox_enb_n = 1;  
        sbox_state = 32'h0000_0000;

        for(int i=0; i<8; i++) 
            {expKey[3][i], expKey[2][i], expKey[1][i], expKey[0][i]} = 32'h0000_0000;
    end
    else begin
        sbox_enb_n = 0;  // enabling Sbox since special transformation requires subByte
        sbox_state = rotWord({prev_expKey[3][5], prev_expKey[2][5], prev_expKey[1][5], prev_expKey[0][5]});  // loading Sbox input
        
        for(int i=0; i<6; i++) begin
            if(i == 0)  // since this index is multiple of 6 it satisfies i%Nk = 0. So special transformation is applied
                {expKey[3][0], expKey[2][0], expKey[1][0], expKey[0][0]} = {prev_expKey[3][0], prev_expKey[2][0], prev_expKey[1][0], prev_expKey[0][0]} ^ subByte ^ RCON[div_Nk(6'(round_num << 2), 6)];
            else  // remaining all indices don't satisfy i%Nk = 0. So normal transformation is applied
                {expKey[3][i], expKey[2][i], expKey[1][i], expKey[0][i]} = {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]} ^ {expKey[3][i-1], expKey[2][i-1], expKey[1][i-1], expKey[0][i-1]};
        end
    end
end

2'b10: begin  // AES-192
    if(round_num == 0) begin  // first round simply uses master KEY
        for(int i=0; i<6; i++)  // simply loading maskter KEY into expKey for further usage
            {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]} <= master_key[(32*i) +: 32];

        for(int i=0; i<4; i++)  // adding round KEY for round-0
            {addRoundKeIt[3][i], addRoundKeIt[2][i], addRoundKeIt[1][i], addRoundKeIt[0][i]} <= {state[3][i], state[2][i], state[1][i], state[0][i]} ^ master_key[(32*i) +: 32];
    end
    else begin  // remianing rounds use expanded KEYs
        case(concatenate_sel(round_num))
            2'b01: begin
                if(sbox_done) begin  // updating the register since sbox_done is high  
                    for(int i=0; i<6; i++)  // updating current round KEYs so that these can be used in next round as previous round KEYs
                        {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]} <= {expKey[3][i], expKey[2][i], expKey[1][i], expKey[0][i]};
                    
                    for(int i=0; i<4; i++)  // adding round KEY
                        {addRoundKeIt[3][i], addRoundKeIt[2][i], addRoundKeIt[1][i], addRoundKeIt[0][i]} <= {state[3][i], state[2][i], state[1][i], state[0][i]} ^ {expKey[3][i], expKey[2][i], expKey[1][i], expKey[0][i]};
                end
                else begin  // holding the previous round KEYs since sbox_done is not high
                    for(int i=0; i<6; i++)
                        {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]} <= {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]};
                    
                    for(int i=0; i<4; i++)
                        {addRoundKeIt[3][i], addRoundKeIt[2][i], addRoundKeIt[1][i], addRoundKeIt[0][i]} <= {addRoundKeIt[3][i], addRoundKeIt[2][i], addRoundKeIt[1][i], addRoundKeIt[0][i]};
                end
            end 
            2'b10: begin
                if(sbox_done) begin  // updating the register since sbox_done is high  
                    for(int i=0; i<6; i++)  // updating current round KEYs so that these can be used in next round as previous round KEYs
                        {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]} <= {expKey[3][i], expKey[2][i], expKey[1][i], expKey[0][i]};
                    
                    for(int i=0; i<4; i++) begin  // adding round KEY
                        if(i < 2)
                            {addRoundKeIt[3][i], addRoundKeIt[2][i], addRoundKeIt[1][i], addRoundKeIt[0][i]} <= {state[3][i], state[2][i], state[1][i], state[0][i]} ^ {prev_expKey[3][i+4], prev_expKey[2][i+4], prev_expKey[1][i+4], prev_expKey[0][i+4]};
                        else 
                            {addRoundKeIt[3][i], addRoundKeIt[2][i], addRoundKeIt[1][i], addRoundKeIt[0][i]} <= {state[3][i], state[2][i], state[1][i], state[0][i]} ^ {expKey[3][i-2], expKey[2][i-2], expKey[1][i-2], expKey[0][i-2]};
                    end
                end
                else begin  // holding the previous round KEYs since sbox_done is not high
                    for(int i=0; i<6; i++)
                        {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]} <= {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]};
                    
                    for(int i=0; i<4; i++)
                        {addRoundKeIt[3][i], addRoundKeIt[2][i], addRoundKeIt[1][i], addRoundKeIt[0][i]} <= {addRoundKeIt[3][i], addRoundKeIt[2][i], addRoundKeIt[1][i], addRoundKeIt[0][i]};
                end
            end
            2'b11: begin  // these rounds don't actually require new expanded KEYs, they use previous KEYs
                for(int i=0; i<6; i++)  // continues to hold the previous round KEYs since new KEYs are not computed
                    {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]} <= {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]};

                for(int i=0; i<4; i++)  // previous KEYs are used as they are sufficient for current round
                    {addRoundKeIt[3][i], addRoundKeIt[2][i], addRoundKeIt[1][i], addRoundKeIt[0][i]} <= {state[3][i], state[2][i], state[1][i], state[0][i]} ^ {prev_expKey[3][i+2], prev_expKey[2][i+2], prev_expKey[1][i+2], prev_expKey[0][i+2]};
            end
            default: begin
                for(int i=0; i<6; i++)
                    {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]} <= {prev_expKey[3][i], prev_expKey[2][i], prev_expKey[1][i], prev_expKey[0][i]};

                for(int i=0; i<4; i++)
                    {addRoundKeIt[3][i], addRoundKeIt[2][i], addRoundKeIt[1][i], addRoundKeIt[0][i]} <= {addRoundKeIt[3][i], addRoundKeIt[2][i], addRoundKeIt[1][i], addRoundKeIt[0][i]};
            end
        endcase
    end
end
```
Looking at this code, we can get a clarity on how those indices are being used in the index range 0-5 every time even though I'm changing rounds. From the mathematical equation `w[i] = w[i-Nk] xor w[i-1] or w[i] = w[i-Nk] xor subword(rotword(w[i-1])) xor RCON[i/Nk]` we can clearly say that `w[i-Nk]` is nothing but the same index word from previous batch and `w[i-1]` is nothing the immediate previous word. 
I am mapping the global, continuous 52-word key schedule down to a rolling **6-word physical register bank** (`expKey[0..5]`). Every time `sbox_done` flashes high, My logic generates a brand-new 6-word generation burst, completely overwriting the register bank with the fresh batch.

---

### Step-by-Step Verification of my Pattern

Let's trace my round numbers (`round_num` or `cipher_round`) and see exactly which index slices of My `prev_expKey` register bank are fed into the `AddRoundKey` engine.

#### **Round 0 (Pre-whitening)**

* My logic loads the 192-bit `master_key` directly into `prev_expKey[0..5]`.
* **Cipher Consumes:** The first 4 columns of the state matrix ($Nb=4$). That means words 0, 1, 2, and 3.
* **My Pattern:** `round-0: {w0, w1, w2, w3}` $\rightarrow$ **MATCH!**
* *Registers untouched:* `w4` and `w5` are left sitting in `prev_expKey[4]` and `prev_expKey[5]`.

#### **Round 1**

* The cipher needs the next 4 words.
* It reads the untouched `w4` and `w5` from the previous state.
* Meanwhile, My FSM triggers a KeyExpansion step. My loop executes, calculates an entire new batch of 6 words based on `prev_expKey`, and overwrites the array. The new words are now sitting in `w0, w1, w2, w3, w4, w5`.
* To get its remaining 2 words, the cipher grabs the newly calculated `w0` and `w1`.
* **My Pattern:** `round-1: {prev(w4, w5), w0, w1}` $\rightarrow$ **MATCH!**
* *Registers untouched:* The new `w2, w3, w4, w5` are left sitting in the registers.

#### **Round 2**

* The cipher needs the next 4 words.
* Since `w2, w3, w4, w5` are already sitting there untouched from the Round 1 generation, the cipher can consume all 4 of them directly from My register bank. No key expansion step is triggered this round.
* **My Pattern:** `round-2: prev{w2, w3, w4, w5}` $\rightarrow$ **MATCH!**
* *Registers untouched:* Absolutely nothing. The entire register bank has been consumed.

#### **Round 3**

* My register bank is completely exhausted, so My FSM triggers another KeyExpansion step.
* An entirely new 6-word batch is computed and written to `w0..w5`.
* The cipher grabs the first 4 words of this brand-new generation.
* **My Pattern:** `round-3: prev{w0, w1, w2, w3}` $\rightarrow$ **MATCH!** (Note: "prev" here refers to the newly updated register batch sitting in My bank at the start of the round).
* *Registers untouched:* `w4` and `w5` are left sitting in the registers.

#### **Round 4**

* The cipher takes the leftover `w4` and `w5`.
* The expansion engine runs again, computing a fresh batch. The cipher grabs the new `w0` and `w1`.
* **My Pattern:** `round-4: {prev(w4, w5), w0, w1}` $\rightarrow$ **MATCH!**

---

### Why My RTL Mathematical Trick Is Correct

My code translates $w[i-Nk]$ to `prev_expKey[i]` and $w[i-1]$ to `expKey[i-1]`. Mathematically, this is flawless for a rolling register bank because:

1. $w[i-Nk]$ translates to "look back exactly 1 full generation batch ago at the exact same index slot," which is exactly what `prev_expKey[i]` holds.
2. $w[i-1]$ translates to "look at the word generated just a moment ago in this same batch compilation," which My loop correctly captures using `expKey[i-1]` (leveraging the blocking assignment chain).

### A Quick Implementation Check for My RTL

My structural logic and indexing pattern are perfectly sound. Since I are building this for hardware, just keep an eye on two small implementation details in My code snippets:

1. **The RCON Index Shift:**
In My code, I use: `RCON[div_Nk(6'(round_num << 2), 6)]`.
Just ensure My custom `div_Nk` function or math resolves to the correct linear round constant index. For AES-192, a new RCON is consumed every time a 6-word block is generated. Because My code generates a new 6-word block on **Round 1, Round 3, Round 4, Round 6, Round 7, Round 9, Round 10, and Round 12**, My RCON lookup should cleanly increment ($1, 2, 3, 4\dots$) sequentially every time `sbox_done` triggers a write.
2. **Combinatorial Loop vs. Clock Domain:**
In My first block, I'm using blocking assignments (`=`) inside a `for` loop to compute `expKey`. In my second block, I'm using non-blocking assignments (`<=`) to latch `expKey` into `prev_expKey` on the clock edge when `sbox_done` is high. This is excellent coding style and separates My combinatorial calculation cleanly from My sequential state registers.


### **AES-192 Word Concatenation Matrix (Rounds 0 to 12)**

| Round Number | AddRoundKey Word Concatenation Pattern | Hardware Action / Register State |
| --- | --- | --- |
| **Round 0** | `{w0, w1, w2, w3}` | **Initial Master Key Setup:** `master_key` loaded into registers. `w4` and `w5` are left untouched. |
| **Round 1** | `{prev(w4, w5), w0, w1}` | **Trigger Key Expansion (Batch 1):** Takes leftover `w4` and `w5` from the Master Key, runs the loop to compute fresh `w0..w5`, and consumes the new `w0` and `w1`. |
| **Round 2** | `prev{w2, w3, w4, w5}` | **Hold Registers:** No key expansion is triggered. The cipher directly consumes the remaining 4 words sitting in the register bank from Batch 1. |
| **Round 3** | `{w0, w1, w2, w3}` | **Trigger Key Expansion (Batch 2):** Registers are empty. Runs the loop to generate fresh `w0..w5` and consumes the first 4 words. `w4` and `w5` are left untouched. |
| **Round 4** | `{prev(w4, w5), w0, w1}` | **Trigger Key Expansion (Batch 3):** Takes leftover `w4` and `w5` from Batch 2, runs the loop to generate fresh `w0..w5`, and consumes the new `w0` and `w1`. |
| **Round 5** | `prev{w2, w3, w4, w5}` | **Hold Registers:** No key expansion is triggered. Consumes the remaining 4 words sitting in the register bank from Batch 3. |
| **Round 6** | `{w0, w1, w2, w3}` | **Trigger Key Expansion (Batch 4):** Runs the loop to generate fresh `w0..w5` and consumes the first 4 words. `w4` and `w5` are left untouched. |
| **Round 7** | `{prev(w4, w5), w0, w1}` | **Trigger Key Expansion (Batch 5):** Takes leftover `w4` and `w5` from Batch 4, runs the loop to generate fresh `w0..w5`, and consumes the new `w0` and `w1`. |
| **Round 8** | `prev{w2, w3, w4, w5}` | **Hold Registers:** No key expansion is triggered. Consumes the remaining 4 words sitting in the register bank from Batch 5. |
| **Round 9** | `{w0, w1, w2, w3}` | **Trigger Key Expansion (Batch 6):** Runs the loop to generate fresh `w0..w5` and consumes the first 4 words. `w4` and `w5` are left untouched. |
| **Round 10** | `{prev(w4, w5), w0, w1}` | **Trigger Key Expansion (Batch 7):** Takes leftover `w4` and `w5` from Batch 6, runs the loop to generate fresh `w0..w5`, and consumes the new `w0` and `w1`. |
| **Round 11** | `prev{w2, w3, w4, w5}` | **Hold Registers:** No key expansion is triggered. Consumes the remaining 4 words sitting in the register bank from Batch 7. |
| **Round 12** | `{w0, w1, w2, w3}` | **Trigger Key Expansion (Batch 8):** Final round. Runs the loop one last time to generate fresh `w0..w5` and consumes the first 4 words (`w0..w3`) to feed the final AddRoundKey stage. |