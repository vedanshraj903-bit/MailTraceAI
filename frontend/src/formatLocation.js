export default function formatLocation(item) {
  if (item.status !== "SUCCESS") {
    return item.status;
  }

  return [item.city, item.region, item.country]
    .filter(Boolean)
    .join(", ") || "Unknown";
}


function formatAxis(value, positive, negative) {
  const hemisphere = value >= 0 ? positive : negative;
  return `${Math.abs(value).toFixed(4)}° ${hemisphere}`;
}

export function formatCoordinates(latitude, longitude) {
  if (typeof latitude !== "number" || typeof longitude !== "number") {
    return "N/A";
  }

  return `${formatAxis(latitude, "N", "S")}, ${formatAxis(longitude, "E", "W")}`;
}
