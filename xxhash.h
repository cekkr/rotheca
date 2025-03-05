/**
 * xxhash.h - Implementazione leggera di XXHash per Mini-Rosetta
 * 
 * Versione semplificata di XXHash, un algoritmo di hashing non crittografico
 * estremamente veloce. Questa implementazione è ottimizzata per le esigenze
 * del sistema di cache di Mini-Rosetta.
 */

 #ifndef XXHASH_H
 #define XXHASH_H
 
 #include <cstdint>
 #include <cstring>
 
 // Costanti per XXH64
 static const uint64_t PRIME64_1 = 11400714785074694791ULL;
 static const uint64_t PRIME64_2 = 14029467366897019727ULL;
 static const uint64_t PRIME64_3 = 1609587929392839161ULL;
 static const uint64_t PRIME64_4 = 9650029242287828579ULL;
 static const uint64_t PRIME64_5 = 2870177450012600261ULL;
 
 // Rotazione a sinistra di 64-bit
 static inline uint64_t XXH_rotl64(uint64_t x, int r) {
     return ((x << r) | (x >> (64 - r)));
 }
 
 // Lettura di un valore a 64-bit
 static inline uint64_t XXH_read64(const void* memptr) {
     uint64_t val;
     memcpy(&val, memptr, sizeof(val));
     return val;
 }
 
 // Funzione di round XXH64
 static inline uint64_t XXH64_round(uint64_t acc, uint64_t input) {
     acc += input * PRIME64_2;
     acc = XXH_rotl64(acc, 31);
     acc *= PRIME64_1;
     return acc;
 }
 
 // Funzione di merging XXH64
 static inline uint64_t XXH64_mergeRound(uint64_t acc, uint64_t val) {
     val = XXH64_round(0, val);
     acc ^= val;
     acc = acc * PRIME64_1 + PRIME64_4;
     return acc;
 }
 
 // Calcolo dell'hash XXH64
 uint64_t XXH64(const void* input, size_t len, uint64_t seed) {
     const uint8_t* p = static_cast<const uint8_t*>(input);
     const uint8_t* bEnd = p + len;
     uint64_t h64;
 
     if (len >= 32) {
         const uint8_t* const limit = bEnd - 32;
         uint64_t v1 = seed + PRIME64_1 + PRIME64_2;
         uint64_t v2 = seed + PRIME64_2;
         uint64_t v3 = seed + 0;
         uint64_t v4 = seed - PRIME64_1;
 
         do {
             v1 = XXH64_round(v1, XXH_read64(p));
             p += 8;
             v2 = XXH64_round(v2, XXH_read64(p));
             p += 8;
             v3 = XXH64_round(v3, XXH_read64(p));
             p += 8;
             v4 = XXH64_round(v4, XXH_read64(p));
             p += 8;
         } while (p <= limit);
 
         h64 = XXH_rotl64(v1, 1) + XXH_rotl64(v2, 7) + XXH_rotl64(v3, 12) + XXH_rotl64(v4, 18);
         h64 = XXH64_mergeRound(h64, v1);
         h64 = XXH64_mergeRound(h64, v2);
         h64 = XXH64_mergeRound(h64, v3);
         h64 = XXH64_mergeRound(h64, v4);
     } else {
         h64 = seed + PRIME64_5;
     }
 
     h64 += static_cast<uint64_t>(len);
 
     // Processa i rimanenti 0-31 bytes
     while (p + 8 <= bEnd) {
         uint64_t k1 = XXH64_round(0, XXH_read64(p));
         h64 ^= k1;
         h64 = XXH_rotl64(h64, 27) * PRIME64_1 + PRIME64_4;
         p += 8;
     }
 
     if (p + 4 <= bEnd) {
         uint32_t k1;
         memcpy(&k1, p, sizeof(k1));
         h64 ^= static_cast<uint64_t>(k1) * PRIME64_1;
         h64 = XXH_rotl64(h64, 23) * PRIME64_2 + PRIME64_3;
         p += 4;
     }
 
     while (p < bEnd) {
         h64 ^= static_cast<uint64_t>(*p) * PRIME64_5;
         h64 = XXH_rotl64(h64, 11) * PRIME64_1;
         p++;
     }
 
     // Avalanche finale
     h64 ^= h64 >> 33;
     h64 *= PRIME64_2;
     h64 ^= h64 >> 29;
     h64 *= PRIME64_3;
     h64 ^= h64 >> 32;
 
     return h64;
 }
 
 // Versione ottimizzata per stringhe
 uint64_t XXH64_string(const char* input, uint64_t seed = 0) {
     if (!input) return 0;
     return XXH64(input, strlen(input), seed);
 }
 
 // Versione incrementale di XXH64 (stato)
 struct XXH64_state_t {
     uint64_t total_len;
     uint64_t v1;
     uint64_t v2;
     uint64_t v3;
     uint64_t v4;
     uint64_t mem64[4];    // Buffer temporaneo per dati non allineati
     uint32_t memsize;     // Numero di byte nel buffer temporaneo
     uint32_t reserved;    // Riservato (allineamento)
 };
 
 // Inizializza lo stato per l'hashing incrementale
 void XXH64_reset(XXH64_state_t* state, uint64_t seed) {
     memset(state, 0, sizeof(*state));
     state->v1 = seed + PRIME64_1 + PRIME64_2;
     state->v2 = seed + PRIME64_2;
     state->v3 = seed + 0;
     state->v4 = seed - PRIME64_1;
     state->total_len = 0;
     state->memsize = 0;
 }
 
 // Aggiunge dati all'hash incrementale
 bool XXH64_update(XXH64_state_t* state, const void* input, size_t len) {
     if (!input) return true;  // Se non ci sono dati, restituisci successo
     
     const uint8_t* p = static_cast<const uint8_t*>(input);
     const uint8_t* const bEnd = p + len;
 
     state->total_len += len;
 
     // Se c'è un buffer parziale, riempilo prima
     if (state->memsize) {
         // Quanto spazio rimane nel buffer?
         uint32_t remaining = 32 - state->memsize;
         
         // Quanti byte possiamo copiare?
         uint32_t to_copy = (len < remaining) ? len : remaining;
 
         // Copia i dati nel buffer
         memcpy(((uint8_t*)state->mem64) + state->memsize, input, to_copy);
         state->memsize += to_copy;
         
         // Se il buffer è pieno, processalo
         if (state->memsize == 32) {
             state->v1 = XXH64_round(state->v1, XXH_read64(state->mem64));
             state->v2 = XXH64_round(state->v2, XXH_read64(state->mem64 + 1));
             state->v3 = XXH64_round(state->v3, XXH_read64(state->mem64 + 2));
             state->v4 = XXH64_round(state->v4, XXH_read64(state->mem64 + 3));
             state->memsize = 0;
         }
         
         // Aggiorna puntatori
         p += to_copy;
     }
 
     // Processa i blocchi completi di 32 byte
     if (p + 32 <= bEnd) {
         const uint8_t* const limit = bEnd - 32;
         uint64_t v1 = state->v1;
         uint64_t v2 = state->v2;
         uint64_t v3 = state->v3;
         uint64_t v4 = state->v4;
 
         do {
             v1 = XXH64_round(v1, XXH_read64(p));
             p += 8;
             v2 = XXH64_round(v2, XXH_read64(p));
             p += 8;
             v3 = XXH64_round(v3, XXH_read64(p));
             p += 8;
             v4 = XXH64_round(v4, XXH_read64(p));
             p += 8;
         } while (p <= limit);
 
         state->v1 = v1;
         state->v2 = v2;
         state->v3 = v3;
         state->v4 = v4;
     }
 
     // Memorizza i byte rimanenti
     if (p < bEnd) {
         memcpy(((uint8_t*)state->mem64) + state->memsize, p, bEnd - p);
         state->memsize += static_cast<uint32_t>(bEnd - p);
     }
 
     return true;
 }
 
 // Calcola l'hash finale
 uint64_t XXH64_digest(const XXH64_state_t* state) {
     uint64_t h64;
 
     if (state->total_len >= 32) {
         // Caso 1: abbiamo processato almeno un blocco completo
         h64 = XXH_rotl64(state->v1, 1) + XXH_rotl64(state->v2, 7) + 
              XXH_rotl64(state->v3, 12) + XXH_rotl64(state->v4, 18);
         h64 = XXH64_mergeRound(h64, state->v1);
         h64 = XXH64_mergeRound(h64, state->v2);
         h64 = XXH64_mergeRound(h64, state->v3);
         h64 = XXH64_mergeRound(h64, state->v4);
     } else {
         // Caso 2: non abbiamo mai processato un blocco completo
         h64 = state->v3 + PRIME64_5;
     }
 
     h64 += static_cast<uint64_t>(state->total_len);
 
     // Processa i rimanenti 0-31 bytes
     const uint8_t* p = (const uint8_t*)state->mem64;
     const uint8_t* const bEnd = p + state->memsize;
 
     while (p + 8 <= bEnd) {
         uint64_t k1 = XXH64_round(0, XXH_read64(p));
         h64 ^= k1;
         h64 = XXH_rotl64(h64, 27) * PRIME64_1 + PRIME64_4;
         p += 8;
     }
 
     if (p + 4 <= bEnd) {
         uint32_t k1;
         memcpy(&k1, p, sizeof(k1));
         h64 ^= static_cast<uint64_t>(k1) * PRIME64_1;
         h64 = XXH_rotl64(h64, 23) * PRIME64_2 + PRIME64_3;
         p += 4;
     }
 
     while (p < bEnd) {
         h64 ^= static_cast<uint64_t>(*p) * PRIME64_5;
         h64 = XXH_rotl64(h64, 11) * PRIME64_1;
         p++;
     }
 
     // Avalanche finale
     h64 ^= h64 >> 33;
     h64 *= PRIME64_2;
     h64 ^= h64 >> 29;
     h64 *= PRIME64_3;
     h64 ^= h64 >> 32;
 
     return h64;
 }
 
 // Implementazione one-shot
 uint64_t XXH64_oneshot(const void* input, size_t len, uint64_t seed) {
     return XXH64(input, len, seed);
 }
 
 #endif // XXHASH_H