export default function StatusBadge({ value }) {

  const cls = value
    .toLowerCase()
    .replace(/\s/g, "-")
    .replace(/\//g, "-");

  return (
    <span className={`statusBadge ${cls}`}>
      {value}
    </span>
  );

}
