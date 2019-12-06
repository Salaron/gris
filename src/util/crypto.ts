import crypto from "crypto"

/**
 * XOR's two input strings (or Buffers)
 *
 * @param a first string or Buffer
 * @param b second string or Buffer
 */
export function xor(a: string | Buffer, b: string | Buffer): Buffer {
  // convert string to Buffer
  if (!Buffer.isBuffer(a)) { a = Buffer.from(a) }
  if (!Buffer.isBuffer(b)) { b = Buffer.from(b) }

  let minLength = a.length
  if (a.length > b.length) minLength = b.length

  const result = []
  for (let i = 0; i < minLength; i++) {
    result.push(a[i] ^ b[i])
  }
  return Buffer.from(result)
}

/**
 * Encrypt input data with AES-128-CBC.
 */
export function aes128cbcEncrypt(data: string, key: Buffer, iv: Buffer) {
  const cipher = crypto.createCipheriv("aes-128-cbc", key, iv)
  const encrypted = cipher.update(data)
  return Buffer.concat([iv, encrypted, cipher.final()]).toString("base64")
}

/**
 * HMAC-SHA1 for X-Message-Code calculation
 *
 * @param data JSON.stringify(requestData)
 * @param key session/sign key
 */
export function hmacSha1(data: string, key: Buffer) {
  return crypto.createHmac("sha1", key).update(data).digest("hex")
}
