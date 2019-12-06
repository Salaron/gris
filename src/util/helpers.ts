/**
 * Returns a number between min and max values (min and max included)
 * @param min minimal number
 * @param max maximal number
 */
export function getRandomNumber(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1) + min)
}

/**
 * Allows use sleep like in Python in an asynchronous function.
 *
 * @param ms time in milliseconds
 */
export function sleep(ms: number): Promise<void> {
  return new Promise((res) => {
    setTimeout(res, ms)
  })
}

/**
 * Compares two software version numbers (e.g. "1.7.1" or "1.2b").
 *
 * This function was born in http://stackoverflow.com/a/6832721.
 *
 * @param {string|number} v1 The first version to be compared.
 * @param {string|number} v2 The second version to be compared.
 * @returns {number|NaN}
 * <ul>
 *    <li>0 if the versions are equal</li>
 *    <li>a negative integer iff v1 < v2</li>
 *    <li>a positive integer iff v1 > v2</li>
 *    <li>NaN if either version string is in the wrong format</li>
 * </ul>
 *
 * @copyright by Jon Papaioannou (["john", "papaioannou"].join(".") + "@gmail.com")
 * @license This function is in the public domain. Do what you want with it, no strings attached.
 */
export function compareVersions(v1: string | number, v2: string | number): -1 | 0 | 1 {
  const v1parts = (v1 as any).split(".").map(Number)
  const v2parts = (v2 as any).split(".").map(Number)

  function isValidPart(x: any) {
    return /^\d+$/.test(x)
  }

  if (!v1parts.every(isValidPart) || !v2parts.every(isValidPart)) throw new Error(`${v1parts} or ${v2parts} is not a valid part`)

  while (v1parts.length < v2parts.length) { v1parts.push(0) }
  while (v2parts.length < v1parts.length) { v2parts.push(0) }

  for (let i = 0; i < v1parts.length; ++i) {
    if (v2parts.length === i) return 1

    if (v1parts[i] === v2parts[i]) continue
    else if (v1parts[i] > v2parts[i]) return 1
    else return -1
  }
  if (v1parts.length !== v2parts.length) { return -1 }
  return 0
}

export function timeStamp(): number {
  return Math.floor(Date.now() / 1000)
}
