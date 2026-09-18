export default function formatLocation(item) {
  if (item.status !== "SUCCESS") {
    return item.status;
  }

  return [item.city, item.region, item.country]
    .filter(Boolean)
    .join(", ") || "Unknown";
}
