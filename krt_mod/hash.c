 // hash.c

#include <linux/random.h>

static unsigned char perm[12];
static unsigned char xor[12];

static void getrnd(void)
{
   get_random_bytes((void *)xor, 12);
   get_random_bytes((void *)perm, 12);
} 

void init_hash(void)
{
  int i, n, j;
  int p[12];
  getrnd();
  for (i = 0; i < 12; i++)
    p[i] = i;
  for (i = 0; i < 12; i++)
  {
    n = perm[i] % (12 - i);
    perm[i] = p[n];
    for(j = 0; j < 11 - n; j++)
      p[n + j] = p[n + j + 1];
  }
}

unsigned int mkhash(uint32_t src, uint16_t sport, uint32_t dest, uint16_t dport)
{
  uint32_t res = 0;
  int i;
  unsigned char data[12];
  uint32_t *stupid = (uint32_t *)data;
  *stupid = src;
  *(uint32_t *)(data + 4) = dest;
  *(uint16_t *)(data + 8) = sport;
  *(uint16_t *)(data + 10) = dport;
  for(i = 0; i < 12; i++)
    res = ((res << 8) + (data[perm[i]] ^ xor[i])) % 0xff100f;
  return res;
}
