import {
  MapContainer,
  TileLayer,
  Marker,
  Polyline,
  Popup,
  Tooltip,
  useMapEvents,
} from "react-leaflet";

import { useState } from "react";

import L from "leaflet";

import "leaflet/dist/leaflet.css";

import formatLocation, { formatCoordinates } from "./formatLocation";


/* ============================================================
   ROLES
   ============================================================ */

const ROLES = {
  SENDER: {
    label: "Sender device",
    description: "Client IP recorded by the sender's webmail",
    color: "#ff6b6b",
  },
  ORIGIN: {
    label: "Sending server",
    description: "Earliest public server in the Received chain",
    color: "#ffa94d",
  },
  RELAY: {
    label: "Relay",
    description: "Intermediate mail server",
    color: "#1992ff",
  },
  FINAL: {
    label: "Receiving server",
    description: "Last public server before delivery",
    color: "#63e6a7",
  },
  UNROUTED: {
    label: "Not in route",
    description: "Public IP not found in the Received chain",
    color: "#8a9bb3",
  },
};


/* ============================================================
   HELPERS
   ============================================================ */

function hasCoordinates(item) {
  return (
    item?.status === "SUCCESS" &&
    typeof item.latitude === "number" &&
    typeof item.longitude === "number"
  );
}

function coordinateKey(item) {
  return `${item.latitude},${item.longitude}`;
}


/*
  Build the ordered list of mapped hops from the relay path.
  Each public relay hop with coordinates becomes one stop,
  in hop order, and gets a role:

    hop 0 (X-Originating-IP)  → SENDER
    first Received hop        → ORIGIN
    last Received hop         → FINAL
    everything in between     → RELAY
*/
function buildStops(geolocation, relayPath) {
  const geoByIp = new Map(
    geolocation.map((item) => [item.ip, item])
  );

  const stops = relayPath
    .filter((hop) => hasCoordinates(geoByIp.get(hop.ip)))
    .map((hop) => ({
      hop: hop.hop,
      ip: hop.ip,
      mayBeForged: Boolean(hop.may_be_forged),
      geo: geoByIp.get(hop.ip),
    }))
    .sort((a, b) => a.hop - b.hop);

  const received = stops.filter((stop) => stop.hop > 0);

  for (const stop of stops) {
    if (stop.hop === 0) {
      stop.role = "SENDER";
    } else if (stop === received[0]) {
      stop.role = "ORIGIN";
    } else if (
      stop === received[received.length - 1] &&
      received.length > 1
    ) {
      stop.role = "FINAL";
    } else {
      stop.role = "RELAY";
    }
  }

  // Geolocated IPs that never appear in the relay path.
  const routedIps = new Set(stops.map((stop) => stop.ip));

  const unrouted = geolocation
    .filter((item) => hasCoordinates(item) && !routedIps.has(item.ip))
    .map((item) => ({
      hop: null,
      ip: item.ip,
      mayBeForged: false,
      geo: item,
      role: "UNROUTED",
    }));

  return { stops, unrouted };
}


/*
  Stops at identical coordinates share one pin; the pin keeps
  every hop number and takes the role of its earliest stop.
*/
function groupIntoPins(stops) {
  const pins = new Map();

  for (const stop of stops) {
    const key = coordinateKey(stop.geo);

    if (!pins.has(key)) {
      pins.set(key, {
        key,
        position: [stop.geo.latitude, stop.geo.longitude],
        label: formatLocation(stop.geo),
        role: stop.role,
        stops: [],
      });
    }

    pins.get(key).stops.push(stop);
  }

  return [...pins.values()];
}


function pinIcon(pin) {
  const hops = pin.stops
    .map((stop) => stop.hop)
    .filter((hop) => hop !== null);

  const text = hops.length > 0
    ? hops.join(",")
    : "?";

  const forged = pin.stops.some((stop) => stop.mayBeForged);

  return L.divIcon({
    className: "",
    html: `<div class="map-pin${forged ? " map-pin-forged" : ""}" style="--pin-color:${ROLES[pin.role].color}">${text}</div>`,
    iconSize: [28, 28],
    iconAnchor: [14, 14],
    popupAnchor: [0, -14],
    tooltipAnchor: [0, -14],
  });
}


/* ============================================================
   SENDER NOTICE
   ============================================================ */

// Common regions per UTC offset, used only as a hint.
const OFFSET_REGIONS = {
  "-08:00": "US/Canada Pacific",
  "-07:00": "US/Canada Mountain or Pacific (summer)",
  "-06:00": "US/Canada Central or Mountain (summer), Mexico",
  "-05:00": "US/Canada Eastern or Central (summer), Colombia, Peru",
  "-04:00": "US/Canada Eastern (summer), Venezuela, Chile",
  "-03:00": "Brazil, Argentina",
  "+00:00": "UK/Ireland/Portugal (winter), West Africa, or UTC",
  "+01:00": "Central Europe (winter), UK/Ireland (summer), Nigeria",
  "+02:00": "Central Europe (summer), Eastern Europe, Egypt, South Africa",
  "+03:00": "Russia (Moscow), Turkey, Saudi Arabia, East Africa",
  "+04:00": "UAE, Oman",
  "+05:00": "Pakistan",
  "+05:30": "India, Sri Lanka",
  "+05:45": "Nepal",
  "+06:00": "Bangladesh",
  "+07:00": "Thailand, Vietnam, Indonesia (West)",
  "+08:00": "China, Singapore, Malaysia, Philippines",
  "+09:00": "Japan, South Korea",
  "+10:00": "Australia (East)",
  "+12:00": "New Zealand",
};

function SenderNotice({ hasSenderIp, hasServers, senderUtcOffset }) {
  if (hasSenderIp && !senderUtcOffset) {
    return null;
  }

  const region = OFFSET_REGIONS[senderUtcOffset];

  return (
    <div className="map-notice">

      {!hasSenderIp && (
        <p>
          <strong>Sender's own IP is not in the headers.</strong>{" "}
          Providers such as Gmail, Outlook.com and Yahoo remove it,
          so the sender's physical location cannot be traced.
          {hasServers && (
            <> The pins show the <em>mail servers</em> the message
            passed through. Server locations are where the IP is
            registered, so large providers often show up at their
            head office (e.g. Google → Mountain View).</>
          )}
        </p>
      )}

      {senderUtcOffset && (
        <p>
          <strong>Sender's clock:</strong>{" "}
          UTC{senderUtcOffset}
          {region && <> ({region})</>}. This comes from the
          email's Date header. It hints at the sender's region
          but can be changed by the sender.
        </p>
      )}

    </div>
  );
}


/* ============================================================
   CURSOR COORDINATES
   ============================================================ */

function CursorCoordinates() {
  const [position, setPosition] = useState(null);

  useMapEvents({
    mousemove: (event) => setPosition(event.latlng.wrap()),
    mouseout: () => setPosition(null),
  });

  return (
    <div className="map-cursor-coordinates">
      {position
        ? formatCoordinates(position.lat, position.lng)
        : "Hover the map for coordinates"}
    </div>
  );
}


/* ============================================================
   LOCATION MAP
   ============================================================ */

export default function LocationMap({
  geolocation,
  relayPath = [],
  senderUtcOffset = null,
}) {
  const { stops, unrouted } = buildStops(geolocation, relayPath);

  const pins = groupIntoPins([...stops, ...unrouted]);

  const notice = (
    <SenderNotice
      hasSenderIp={stops.some((stop) => stop.role === "SENDER")}
      hasServers={pins.length > 0}
      senderUtcOffset={senderUtcOffset}
    />
  );

  if (pins.length === 0) {
    return (
      <>
        {notice}
        <p className="muted">
          No IP locations could be resolved for mapping.
        </p>
      </>
    );
  }

  // Route follows hop order; consecutive hops in the same
  // place collapse into one point.
  const route = [];

  for (const stop of stops) {
    const point = [stop.geo.latitude, stop.geo.longitude];
    const previous = route[route.length - 1];

    if (!previous || previous[0] !== point[0] || previous[1] !== point[1]) {
      route.push(point);
    }
  }

  const usedRoles = Object.keys(ROLES).filter((role) =>
    pins.some((pin) => pin.stops.some((stop) => stop.role === role))
  );

  return (
    <div className="location-map">

      {notice}

      <MapContainer
        bounds={pins.map((pin) => pin.position)}
        boundsOptions={{ padding: [50, 50], maxZoom: 8 }}
        scrollWheelZoom={false}
        worldCopyJump
      >

        <TileLayer
          url="https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}"
          attribution="Tiles &copy; Esri &mdash; Esri, HERE, Garmin, &copy; OpenStreetMap contributors"
          maxZoom={16}
        />

        <TileLayer
          url="https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Reference/MapServer/tile/{z}/{y}/{x}"
          maxZoom={16}
        />

        {route.length > 1 && (
          <Polyline
            positions={route}
            pathOptions={{
              color: "#1992ff",
              weight: 2,
              dashArray: "6 6",
            }}
          />
        )}

        {pins.map((pin) => (
          <Marker
            key={pin.key}
            position={pin.position}
            icon={pinIcon(pin)}
          >

            <Tooltip direction="top">
              {ROLES[pin.role].label} · {pin.label}
            </Tooltip>

            <Popup>
              <div className="map-popup">
                <strong>{pin.label}</strong>

                <div className="map-popup-coordinates">
                  {formatCoordinates(pin.position[0], pin.position[1])}
                </div>

                {pin.stops.map((stop) => (
                  <div key={`${stop.hop}-${stop.ip}`} className="map-popup-ip">

                    <div
                      className="map-popup-role"
                      style={{ color: ROLES[stop.role].color }}
                    >
                      {stop.hop !== null && `Hop ${stop.hop} · `}
                      {ROLES[stop.role].label}
                    </div>

                    <code>{stop.ip}</code>

                    <div>
                      {stop.geo.isp || stop.geo.asn_name || "Unknown ISP"}
                    </div>

                    <div className="muted">
                      {[stop.geo.asn, stop.geo.timezone]
                        .filter(Boolean)
                        .join(" · ")}
                    </div>

                    {stop.mayBeForged && (
                      <div className="map-popup-warning">
                        Receiving server flagged this hop as possibly forged
                      </div>
                    )}

                  </div>
                ))}
              </div>
            </Popup>

          </Marker>
        ))}

        <CursorCoordinates />

      </MapContainer>

      <div className="map-legend">
        {usedRoles.map((role) => (
          <span key={role} title={ROLES[role].description}>
            <i style={{ background: ROLES[role].color }} />
            {ROLES[role].label}
          </span>
        ))}
        <span className="map-legend-note">
          Numbers are hop order (0 = sender device)
        </span>
      </div>

    </div>
  );
}
