// // aes.js - AES encryption/decryption implementation without crypto library

// // Constants for AES
// const Nb = 4;         // Number of columns in state (fixed at 4 for AES)
// const Nr = 10;        // Number of rounds (10 for AES-128)
// const Nk = 4;         // Number of 32-bit words in key (4 for AES-128)

// // Substitution box (S-box)
// const sBox = [
//     0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
//     0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
//     0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
//     0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
//     0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
//     0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
//     0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
//     0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
//     0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
//     0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
//     0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
//     0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
//     0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
//     0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
//     0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
//     0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
// ];

// // Inverse Substitution box (inverse S-box)
// const invSBox = [
//     0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
//     0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
//     0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
//     0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
//     0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
//     0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
//     0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
//     0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
//     0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
//     0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
//     0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
//     0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
//     0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
//     0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
//     0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
//     0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
// ];

// // Round constant used for key expansion
// const rCon = [
//     [0x00, 0x00, 0x00, 0x00],
//     [0x01, 0x00, 0x00, 0x00],
//     [0x02, 0x00, 0x00, 0x00],
//     [0x04, 0x00, 0x00, 0x00],
//     [0x08, 0x00, 0x00, 0x00],
//     [0x10, 0x00, 0x00, 0x00],
//     [0x20, 0x00, 0x00, 0x00],
//     [0x40, 0x00, 0x00, 0x00],
//     [0x80, 0x00, 0x00, 0x00],
//     [0x1b, 0x00, 0x00, 0x00],
//     [0x36, 0x00, 0x00, 0x00]
// ];

// // AES SubBytes - Substitute bytes using S-box
// function subBytes(state) {
//     for (let i = 0; i < 4; i++) {
//         for (let j = 0; j < Nb; j++) {
//             state[i][j] = sBox[state[i][j]];
//         }
//     }
//     return state;
// }

// // AES InvSubBytes - Substitute bytes using inverse S-box
// function invSubBytes(state) {
//     for (let i = 0; i < 4; i++) {
//         for (let j = 0; j < Nb; j++) {
//             state[i][j] = invSBox[state[i][j]];
//         }
//     }
//     return state;
// }

// // AES ShiftRows - Shift rows of state array
// function shiftRows(state) {
//     let temp;

//     // No shift for row 0

//     // Shift row 1 by 1
//     temp = state[1][0];
//     state[1][0] = state[1][1];
//     state[1][1] = state[1][2];
//     state[1][2] = state[1][3];
//     state[1][3] = temp;

//     // Shift row 2 by 2
//     temp = state[2][0];
//     state[2][0] = state[2][2];
//     state[2][2] = temp;
//     temp = state[2][1];
//     state[2][1] = state[2][3];
//     state[2][3] = temp;

//     // Shift row 3 by 3
//     temp = state[3][3];
//     state[3][3] = state[3][2];
//     state[3][2] = state[3][1];
//     state[3][1] = state[3][0];
//     state[3][0] = temp;

//     return state;
// }

// // AES InvShiftRows - Inverse shift rows of state array
// function invShiftRows(state) {
//     let temp;

//     // No shift for row 0

//     // Shift row 1 by 3
//     temp = state[1][3];
//     state[1][3] = state[1][2];
//     state[1][2] = state[1][1];
//     state[1][1] = state[1][0];
//     state[1][0] = temp;

//     // Shift row 2 by 2
//     temp = state[2][0];
//     state[2][0] = state[2][2];
//     state[2][2] = temp;
//     temp = state[2][1];
//     state[2][1] = state[2][3];
//     state[2][3] = temp;

//     // Shift row 3 by 1
//     temp = state[3][0];
//     state[3][0] = state[3][1];
//     state[3][1] = state[3][2];
//     state[3][2] = state[3][3];
//     state[3][3] = temp;

//     return state;
// }

// // Galois field multiplication (GF(2^8))
// function galoisMult(a, b) {
//     let p = 0;
//     let hiBitSet;

//     for (let i = 0; i < 8; i++) {
//         if ((b & 1) !== 0) {
//             p ^= a;
//         }

//         hiBitSet = (a & 0x80);
//         a <<= 1;
//         if (hiBitSet !== 0) {
//             a ^= 0x1b; // XOR with the irreducible polynomial x^8 + x^4 + x^3 + x + 1
//         }

//         b >>= 1;
//     }

//     return p & 0xff;
// }

// // AES MixColumns - Mix columns of state array
// function mixColumns(state) {
//     let temp = new Array(4);

//     for (let j = 0; j < Nb; j++) {
//         for (let i = 0; i < 4; i++) {
//             temp[i] = state[i][j];
//         }

//         state[0][j] = galoisMult(temp[0], 2) ^ galoisMult(temp[1], 3) ^ temp[2] ^ temp[3];
//         state[1][j] = temp[0] ^ galoisMult(temp[1], 2) ^ galoisMult(temp[2], 3) ^ temp[3];
//         state[2][j] = temp[0] ^ temp[1] ^ galoisMult(temp[2], 2) ^ galoisMult(temp[3], 3);
//         state[3][j] = galoisMult(temp[0], 3) ^ temp[1] ^ temp[2] ^ galoisMult(temp[3], 2);
//     }

//     return state;
// }

// // AES InvMixColumns - Inverse mix columns of state array
// function invMixColumns(state) {
//     let temp = new Array(4);

//     for (let j = 0; j < Nb; j++) {
//         for (let i = 0; i < 4; i++) {
//             temp[i] = state[i][j];
//         }

//         state[0][j] = galoisMult(temp[0], 0x0e) ^ galoisMult(temp[1], 0x0b) ^ galoisMult(temp[2], 0x0d) ^ galoisMult(temp[3], 0x09);
//         state[1][j] = galoisMult(temp[0], 0x09) ^ galoisMult(temp[1], 0x0e) ^ galoisMult(temp[2], 0x0b) ^ galoisMult(temp[3], 0x0d);
//         state[2][j] = galoisMult(temp[0], 0x0d) ^ galoisMult(temp[1], 0x09) ^ galoisMult(temp[2], 0x0e) ^ galoisMult(temp[3], 0x0b);
//         state[3][j] = galoisMult(temp[0], 0x0b) ^ galoisMult(temp[1], 0x0d) ^ galoisMult(temp[2], 0x09) ^ galoisMult(temp[3], 0x0e);
//     }

//     return state;
// }

// // AES AddRoundKey - XOR state with round key
// function addRoundKey(state, roundKey, round) {
//     for (let i = 0; i < 4; i++) {
//         for (let j = 0; j < Nb; j++) {
//             state[i][j] ^= roundKey[round * 4 + j][i];
//         }
//     }

//     return state;
// }

// // Rotate word (used in key expansion)
// function rotWord(word) {
//     let temp = word[0];
//     for (let i = 0; i < 3; i++) {
//         word[i] = word[i + 1];
//     }
//     word[3] = temp;

//     return word;
// }

// // Apply S-box to each byte in word (used in key expansion)
// function subWord(word) {
//     for (let i = 0; i < 4; i++) {
//         word[i] = sBox[word[i]];
//     }

//     return word;
// }

// // Key Expansion - Expand the key into the key schedule
// function keyExpansion(key) {
//     let w = new Array(Nb * (Nr + 1));
//     let temp = new Array(4);

//     // Initialize first Nk words with the cipher key
//     let i = 0;
//     while (i < Nk) {
//         w[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
//         i++;
//     }

//     // Expand the key schedule
//     i = Nk;
//     while (i < Nb * (Nr + 1)) {
//         temp = w[i - 1].slice();

//         if (i % Nk === 0) {
//             temp = subWord(rotWord(temp));
//             for (let j = 0; j < 4; j++) {
//                 temp[j] ^= rCon[i / Nk][j];
//             }
//         } else if (Nk > 6 && i % Nk === 4) {
//             temp = subWord(temp);
//         }

//         w[i] = new Array(4);
//         for (let j = 0; j < 4; j++) {
//             w[i][j] = w[i - Nk][j] ^ temp[j];
//         }

//         i++;
//     }

//     return w;
// }

// // Convert text string to byte array
// function textToBytes(text) {
//     const bytes = new Array(text.length);
//     for (let i = 0; i < text.length; i++) {
//         bytes[i] = text.charCodeAt(i) & 0xff;
//     }
//     return bytes;
// }

// // Convert byte array to text string
// function bytesToText(bytes) {
//     let text = '';
//     for (let i = 0; i < bytes.length; i++) {
//         text += String.fromCharCode(bytes[i]);
//     }
//     return text;
// }

// // Pad data to a multiple of 16 bytes (AES block size)
// function padData(data) {
//     const blockSize = 16;
//     const padLength = blockSize - (data.length % blockSize);
//     const paddedData = new Array(data.length + padLength);

//     for (let i = 0; i < data.length; i++) {
//         paddedData[i] = data[i];
//     }

//     // Use PKCS#7 padding - all padding bytes have the value of the padding length
//     for (let i = data.length; i < paddedData.length; i++) {
//         paddedData[i] = padLength;
//     }

//     return paddedData;
// }

// // Remove padding from data
// function unpadData(data) {
//     // Get the padding length from the last byte
//     const padLength = data[data.length - 1];

//     // Check if the padding is valid
//     if (padLength > 16) {
//         throw new Error('Invalid padding');
//     }

//     // Remove padding bytes
//     return data.slice(0, data.length - padLength);
// }

// // AES Encryption - Encrypt a 16-byte block
// function encryptBlock(input, w) {
//     // Initialize state array from input block
//     let state = new Array(4);
//     for (let i = 0; i < 4; i++) {
//         state[i] = new Array(Nb);
//     }

//     for (let i = 0; i < 4; i++) {
//         for (let j = 0; j < Nb; j++) {
//             state[i][j] = input[i + 4 * j];
//         }
//     }

//     // Initial round - Add Round Key
//     state = addRoundKey(state, w, 0);

//     // Main rounds
//     for (let round = 1; round < Nr; round++) {
//         state = subBytes(state);
//         state = shiftRows(state);
//         state = mixColumns(state);
//         state = addRoundKey(state, w, round);
//     }

//     // Final round (no MixColumns)
//     state = subBytes(state);
//     state = shiftRows(state);
//     state = addRoundKey(state, w, Nr);

//     // Convert state array to output block
//     let output = new Array(16);
//     for (let i = 0; i < 4; i++) {
//         for (let j = 0; j < Nb; j++) {
//             output[i + 4 * j] = state[i][j];
//         }
//     }

//     return output;
// }

// // AES Decryption - Decrypt a 16-byte block
// function decryptBlock(input, w) {
//     // Initialize state array from input block
//     let state = new Array(4);
//     for (let i = 0; i < 4; i++) {
//         state[i] = new Array(Nb);
//     }

//     for (let i = 0; i < 4; i++) {
//         for (let j = 0; j < Nb; j++) {
//             state[i][j] = input[i + 4 * j];
//         }
//     }

//     // Initial round - Add Round Key
//     state = addRoundKey(state, w, Nr);

//     // Main rounds (reverse order)
//     for (let round = Nr - 1; round > 0; round--) {
//         state = invShiftRows(state);
//         state = invSubBytes(state);
//         state = addRoundKey(state, w, round);
//         state = invMixColumns(state);
//     }

//     // Final round (no InvMixColumns)
//     state = invShiftRows(state);
//     state = invSubBytes(state);
//     state = addRoundKey(state, w, 0);

//     // Convert state array to output block
//     let output = new Array(16);
//     for (let i = 0; i < 4; i++) {
//         for (let j = 0; j < Nb; j++) {
//             output[i + 4 * j] = state[i][j];
//         }
//     }

//     return output;
// }

// // Encrypt the input data using AES
// function encrypt(input, key) {
//     // Convert text to bytes and pad to block size
//     const inputBytes = padData(textToBytes(input));
//     const keyBytes = textToBytes(key.slice(0, 16).padEnd(16, ' '));

//     // Key expansion
//     const w = keyExpansion(keyBytes);

//     // Process each 16-byte block
//     const output = new Array(inputBytes.length);
//     for (let i = 0; i < inputBytes.length; i += 16) {
//         const block = inputBytes.slice(i, i + 16);
//         const encryptedBlock = encryptBlock(block, w);

//         for (let j = 0; j < 16; j++) {
//             output[i + j] = encryptedBlock[j];
//         }
//     }

//     // Convert encrypted bytes to Base64 string for readability
//     return btoa(String.fromCharCode.apply(null, output));
// }

// // Decrypt the encrypted data using AES
// function decrypt(input, key) {
//     try {
//         // Convert Base64 string to bytes
//         const encryptedBytes = Array.from(atob(input), c => c.charCodeAt(0));
//         const keyBytes = textToBytes(key.slice(0, 16).padEnd(16, ' '));

//         // Key expansion
//         const w = keyExpansion(keyBytes);

//         // Process each 16-byte block
//         const output = new Array(encryptedBytes.length);
//         for (let i = 0; i < encryptedBytes.length; i += 16) {
//             const block = encryptedBytes.slice(i, i + 16);
//             const decryptedBlock = decryptBlock(block, w);

//             for (let j = 0; j < 16; j++) {
//                 output[i + j] = decryptedBlock[j];
//             }
//         }

//         // Unpad the decrypted bytes and convert to text
//         return bytesToText(unpadData(output));
//     } catch (error) {
//         console.error('Decryption error:', error);
//         return 'Decryption error: ' + error.message;
//     }
// }

// export { encrypt, decrypt };

















// aes.js - AES encryption/decryption implementation with UTF-8 support for Vietnamese

// Constants for AES
const Nb = 4;         // Number of columns in state (fixed at 4 for AES)
const Nr = 10;        // Number of rounds (10 for AES-128)
const Nk = 4;         // Number of 32-bit words in key (4 for AES-128)

// Substitution box (S-box)
const sBox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
];

// Inverse Substitution box (inverse S-box)
const invSBox = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
];

// Round constant used for key expansion
const rCon = [
    [0x00, 0x00, 0x00, 0x00],
    [0x01, 0x00, 0x00, 0x00],
    [0x02, 0x00, 0x00, 0x00],
    [0x04, 0x00, 0x00, 0x00],
    [0x08, 0x00, 0x00, 0x00],
    [0x10, 0x00, 0x00, 0x00],
    [0x20, 0x00, 0x00, 0x00],
    [0x40, 0x00, 0x00, 0x00],
    [0x80, 0x00, 0x00, 0x00],
    [0x1b, 0x00, 0x00, 0x00],
    [0x36, 0x00, 0x00, 0x00]
];

// AES SubBytes - Substitute bytes using S-box
function subBytes(state) {
    for (let i = 0; i < 4; i++) {
        for (let j = 0; j < Nb; j++) {
            state[i][j] = sBox[state[i][j]];
        }
    }
    return state;
}

// AES InvSubBytes - Substitute bytes using inverse S-box
function invSubBytes(state) {
    for (let i = 0; i < 4; i++) {
        for (let j = 0; j < Nb; j++) {
            state[i][j] = invSBox[state[i][j]];
        }
    }
    return state;
}

// AES ShiftRows - Shift rows of state array
function shiftRows(state) {
    let temp;

    // No shift for row 0
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    temp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = temp;

    return state;
}

// AES InvShiftRows - Inverse shift rows of state array
function invShiftRows(state) {
    let temp;

    temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;

    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;

    return state;
}

// Galois field multiplication (GF(2^8))
function galoisMult(a, b) {
    let p = 0;
    let hiBitSet;

    for (let i = 0; i < 8; i++) {
        if ((b & 1) !== 0) {
            p ^= a;
        }
        hiBitSet = (a & 0x80);
        a <<= 1;
        if (hiBitSet !== 0) {
            a ^= 0x1b; // XOR with the irreducible polynomial x^8 + x^4 + x^3 + x + 1
        }
        b >>= 1;
    }

    return p & 0xff;
}

// AES MixColumns - Mix columns of state array
function mixColumns(state) {
    let temp = new Array(4);

    for (let j = 0; j < Nb; j++) {
        for (let i = 0; i < 4; i++) {
            temp[i] = state[i][j];
        }
        state[0][j] = galoisMult(temp[0], 2) ^ galoisMult(temp[1], 3) ^ temp[2] ^ temp[3];
        state[1][j] = temp[0] ^ galoisMult(temp[1], 2) ^ galoisMult(temp[2], 3) ^ temp[3];
        state[2][j] = temp[0] ^ temp[1] ^ galoisMult(temp[2], 2) ^ galoisMult(temp[3], 3);
        state[3][j] = galoisMult(temp[0], 3) ^ temp[1] ^ temp[2] ^ galoisMult(temp[3], 2);
    }

    return state;
}

// AES InvMixColumns - Inverse mix columns of state array
function invMixColumns(state) {
    let temp = new Array(4);

    for (let j = 0; j < Nb; j++) {
        for (let i = 0; i < 4; i++) {
            temp[i] = state[i][j];
        }
        state[0][j] = galoisMult(temp[0], 0x0e) ^ galoisMult(temp[1], 0x0b) ^ galoisMult(temp[2], 0x0d) ^ galoisMult(temp[3], 0x09);
        state[1][j] = galoisMult(temp[0], 0x09) ^ galoisMult(temp[1], 0x0e) ^ galoisMult(temp[2], 0x0b) ^ galoisMult(temp[3], 0x0d);
        state[2][j] = galoisMult(temp[0], 0x0d) ^ galoisMult(temp[1], 0x09) ^ galoisMult(temp[2], 0x0e) ^ galoisMult(temp[3], 0x0b);
        state[3][j] = galoisMult(temp[0], 0x0b) ^ galoisMult(temp[1], 0x0d) ^ galoisMult(temp[2], 0x09) ^ galoisMult(temp[3], 0x0e);
    }

    return state;
}

// AES AddRoundKey - XOR state with round key
function addRoundKey(state, roundKey, round) {
    for (let i = 0; i < 4; i++) {
        for (let j = 0; j < Nb; j++) {
            state[i][j] ^= roundKey[round * 4 + j][i];
        }
    }
    return state;
}

// Rotate word (used in key expansion)
function rotWord(word) {
    let temp = word[0];
    for (let i = 0; i < 3; i++) {
        word[i] = word[i + 1];
    }
    word[3] = temp;
    return word;
}

// Apply S-box to each byte in word (used in key expansion)
function subWord(word) {
    for (let i = 0; i < 4; i++) {
        word[i] = sBox[word[i]];
    }
    return word;
}

// Key Expansion - Expand the key into the key schedule
function keyExpansion(key) {
    let w = new Array(Nb * (Nr + 1));
    let temp = new Array(4);

    let i = 0;
    while (i < Nk) {
        w[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
        i++;
    }

    i = Nk;
    while (i < Nb * (Nr + 1)) {
        temp = w[i - 1].slice();

        if (i % Nk === 0) {
            temp = subWord(rotWord(temp));
            for (let j = 0; j < 4; j++) {
                temp[j] ^= rCon[i / Nk][j];
            }
        } else if (Nk > 6 && i % Nk === 4) {
            temp = subWord(temp);
        }

        w[i] = new Array(4);
        for (let j = 0; j < 4; j++) {
            w[i][j] = w[i - Nk][j] ^ temp[j];
        }
        i++;
    }

    return w;
}

// Convert text string to byte array with UTF-8 encoding
function textToBytes(text) {
    const encoder = new TextEncoder();
    return encoder.encode(text);
}

// Convert byte array to text string with UTF-8 decoding
function bytesToText(bytes) {
    const decoder = new TextDecoder('utf-8');
    return decoder.decode(new Uint8Array(bytes));
}

// Pad data to a multiple of 16 bytes (AES block size)
function padData(data) {
    const blockSize = 16;
    const padLength = blockSize - (data.length % blockSize);
    const paddedData = new Uint8Array(data.length + padLength);

    paddedData.set(data);
    for (let i = data.length; i < paddedData.length; i++) {
        paddedData[i] = padLength; // PKCS#7 padding
    }

    return paddedData;
}

// Remove padding from data
function unpadData(data) {
    const padLength = data[data.length - 1];
    if (padLength > 16) {
        throw new Error('Invalid padding');
    }
    return data.slice(0, data.length - padLength);
}

// AES Encryption - Encrypt a 16-byte block
function encryptBlock(input, w) {
    let state = new Array(4);
    for (let i = 0; i < 4; i++) {
        state[i] = new Array(Nb);
    }

    for (let i = 0; i < 4; i++) {
        for (let j = 0; j < Nb; j++) {
            state[i][j] = input[i + 4 * j];
        }
    }

    state = addRoundKey(state, w, 0);

    for (let round = 1; round < Nr; round++) {
        state = subBytes(state);
        state = shiftRows(state);
        state = mixColumns(state);
        state = addRoundKey(state, w, round);
    }

    state = subBytes(state);
    state = shiftRows(state);
    state = addRoundKey(state, w, Nr);

    let output = new Array(16);
    for (let i = 0; i < 4; i++) {
        for (let j = 0; j < Nb; j++) {
            output[i + 4 * j] = state[i][j];
        }
    }

    return output;
}

// AES Decryption - Decrypt a 16-byte block
function decryptBlock(input, w) {
    let state = new Array(4);
    for (let i = 0; i < 4; i++) {
        state[i] = new Array(Nb);
    }

    for (let i = 0; i < 4; i++) {
        for (let j = 0; j < Nb; j++) {
            state[i][j] = input[i + 4 * j];
        }
    }

    state = addRoundKey(state, w, Nr);

    for (let round = Nr - 1; round > 0; round--) {
        state = invShiftRows(state);
        state = invSubBytes(state);
        state = addRoundKey(state, w, round);
        state = invMixColumns(state);
    }

    state = invShiftRows(state);
    state = invSubBytes(state);
    state = addRoundKey(state, w, 0);

    let output = new Array(16);
    for (let i = 0; i < 4; i++) {
        for (let j = 0; j < Nb; j++) {
            output[i + 4 * j] = state[i][j];
        }
    }

    return output;
}

// Encrypt the input data using AES
function encrypt(input, key) {
    const inputBytes = padData(textToBytes(input));
    const keyBytes = textToBytes(key.slice(0, 16).padEnd(16, ' '));

    const w = keyExpansion(keyBytes);

    const output = new Uint8Array(inputBytes.length);
    for (let i = 0; i < inputBytes.length; i += 16) {
        const block = inputBytes.slice(i, i + 16);
        const encryptedBlock = encryptBlock(block, w);
        output.set(encryptedBlock, i);
    }

    return btoa(String.fromCharCode(...output));
}

// Decrypt the encrypted data using AES
function decrypt(input, key) {
    try {
        const encryptedBytes = Uint8Array.from(atob(input), c => c.charCodeAt(0));
        const keyBytes = textToBytes(key.slice(0, 16).padEnd(16, ' '));

        const w = keyExpansion(keyBytes);

        const output = new Uint8Array(encryptedBytes.length);
        for (let i = 0; i < encryptedBytes.length; i += 16) {
            const block = encryptedBytes.slice(i, i + 16);
            const decryptedBlock = decryptBlock(block, w);
            output.set(decryptedBlock, i);
        }

        return bytesToText(unpadData(output));
    } catch (error) {
        console.error('Decryption error:', error);
        return 'Decryption error: ' + error.message;
    }
}

// Export functions
export { encrypt, decrypt };

// Test example (runs in Node.js)
if (typeof window === 'undefined') {
    const key = "MySecretKey12345";
    const plaintext = "Xin chào, đây là tiếng Việt!";

    const encrypted = encrypt(plaintext, key);
    console.log("Encrypted:", encrypted);

    const decrypted = decrypt(encrypted, key);
    console.log("Decrypted:", decrypted);
}