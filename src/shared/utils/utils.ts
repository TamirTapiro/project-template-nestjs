export function convertArrayToObject(arr: string[]): {
  [key: string]: boolean;
} {
  const result: { [key: string]: boolean } = {};
  arr.forEach((item) => {
    result[item] = true;
  });
  return result;
}
