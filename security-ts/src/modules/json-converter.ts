export const JSONConverter = <T>(_key: unknown, value: T): T | string => {
  if (typeof value === "number") {
    if (value.toFixed(9).endsWith(".000000000")) {
      return `${value}.0`;
    } else {
      return `${value}`;
    }
  }
  return value;
};
