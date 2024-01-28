/* Implementation of the Ascon cipher */
#include <stdio.h>
typedef unsigned long long bit64;

bit64 constants[16] = {
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
    0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f
};
bit64 state[5] = { 0 }, t[5] = { 0 };
bit64 rotate(bit64 x, int n)
{
    return (x >> n) ^ (x << (64 - n));
}
bit64 print_state(bit64 state[5])
{
    printf("State: %llx %llx %llx %llx %llx\n", state[0], state[1], state[2], state[3], state[4]);
    return 0;
}

void linear(bit64 state[5])
{
    bit64 temp0, temp1;
    temp0 = rotate(state[0], 19);
    temp1 = rotate(state[0], 28);
    state[0] ^= temp0 ^ temp1;
    temp0 = rotate(state[1], 61);
    temp1 = rotate(state[1], 39);
    state[1] ^= temp0 ^ temp1;
    temp0 = rotate(state[2], 1);
    temp1 = rotate(state[2], 6);
    state[2] ^= temp0 ^ temp1;
    temp0 = rotate(state[3], 10);
    temp1 = rotate(state[3], 17);
    state[3] ^= temp0 ^ temp1;
    temp0 = rotate(state[4], 7);
    temp1 = rotate(state[4], 41);
    state[4] ^= temp0 ^ temp1;
}

void sbox(bit64 x[5])
{
    /**
     * Bitslice implementation of the Ascon S-box taken from the Ascon 
     * specification document.
     */

    x[0] ^= x[4]; x[4] ^= x[3]; x[2] ^= x[1];
    t[0] = x[0]; t[1] = x[1]; t[2] = x[2]; t[3] = x[3]; t[4] = x[4];
    t[0] = ~t[0]; t[1] = ~t[1]; t[2] = ~t[2]; t[3] = ~t[3]; t[4] = ~t[4];
    t[0] &= x[1]; t[1] &= x[2]; t[2] &= x[3]; t[3] &= x[4]; t[4] &= x[0];
    x[0] ^= t[1]; x[1] ^= t[2]; x[2] ^= t[3]; x[3] ^= t[4]; x[4] ^= t[0];
    x[1] ^= x[0]; x[0] ^= x[4]; x[3] ^= x[2]; x[2] = ~x[2];
}

void add_constant(bit64 state[5], int i, int a)
{
    state[2] ^= constants[12 - a + i];
}

void permutation(bit64 state[5], int a)
{
    for (int i = 0; i < a; i++)
    {
        add_constant(state, i, a);
        sbox(state);
        linear(state);
    }
}

void init(bit64 state[5], bit64 key[2])
{
    permutation(state, 12);
    state[3] ^= key[0];
    state[4] ^= key[1];
}

void encrypt(bit64 state[5], int length, bit64 plaintext[], bit64 ciphertext[])
{
    ciphertext[0] = plaintext[0] ^ state[0];
    for (int i = 1; i < length; i++){
        permutation(state, 6);
        ciphertext[i] = plaintext[i] ^ state[0];
        state[0] ^= ciphertext[i];
    }
}

void decrypt(bit64 state[5], int length, bit64 plaintext[], bit64 ciphertext[]) {
	ciphertext[0] = plaintext[0] ^ state[0];
	for (int i = 1; i < length; i++) {
		permutation(state, 6);
		ciphertext[i] = plaintext[i] ^ state[0];
		state[0] = plaintext[i];
	}
}

void finalize(bit64 state[5], bit64 key[2])
{
    state[1] ^= key[0];
    state[2] ^= key[1];
    permutation(state, 12);
    state[3] ^= key[0];
    state[4] ^= key[1];
}

void verify(bit64 state[5], bit64 tag[2])
{
    if (state[3] == tag[0] && state[4] == tag[1])
        printf("Tag is valid\n");
    else
        printf("Tag is invalid\n");
}

int main()
{
    bit64 nonce[2] = { 0 };
    bit64 key[2] = { 0 };
    bit64 tag[2] = { 0 };
    bit64 IV = 0x80400c0600000000;
    bit64 plaintext[] = { 0x1234567890abcdef, 0x82187 }, ciphertext[10] = { 0 };

    /* Inital state */
    state[0] = IV;
    state[1] = key[0];
    state[2] = key[1];
    state[3] = nonce[0];
    state[4] = nonce[1];
    init(state, key);
    print_state(state);

    /* Encryption */
    encrypt(state, 2, plaintext, ciphertext);
    printf("Ciphertext: %llx %llx\n", ciphertext[0], ciphertext[1]);
    finalize(state, key);
    printf("Tag: %llx %llx\n", state[3], state[4]);


    /* Decryption */ 
    state[0] = IV;
    state[1] = key[0];
    state[2] = key[1];
    state[3] = nonce[0];
    state[4] = nonce[1];
    init(state, key);
    print_state(state);
    decrypt(state, 2, ciphertext, plaintext);
    printf("Decrypted: %llx %llx\n", plaintext[0], plaintext[1]);

    /* Verify */
    tag[0] = state[3];
    tag[1] = state[4];
    verify(state, tag);

    return 0;
}
