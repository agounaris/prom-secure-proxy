import time
from opentelemetry import metrics
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.exporter.prometheus_remote_write import (
    PrometheusRemoteWriteMetricsExporter,
)

REMOTE_WRITE_URL = "http://localhost:9090/api/v1/write"

# Optional headers for auth
HEADERS = {
    # "Authorization": "Bearer <token>",
}

def main():
    # Setup exporter
    exporter = PrometheusRemoteWriteMetricsExporter(
        endpoint=REMOTE_WRITE_URL,
        headers=HEADERS,
    )

    # Setup reader with export interval (in milliseconds)
    reader = PeriodicExportingMetricReader(exporter, export_interval_millis=5000)

    # Setup meter provider
    provider = MeterProvider(metric_readers=[reader])
    metrics.set_meter_provider(provider)

    # Get meter
    meter = metrics.get_meter(__name__)

    # Create counter
    counter = meter.create_counter(
        name="my_custom_counter",
        description="An example counter",
        unit="total",
    )

    # Increment counter continuously
    while True:
        counter.add(4, {"label1": "value2", "tenant_id":"default-tenant"})
        counter.add(5, {"label1": "value1", "tenant_id":"tenant1"})
        counter.add(6, {"label1": "value1", "tenant_id":"tenant2"})
        counter.add(6, {"label1": "value1"})
        print("Incremented counter")
        time.sleep(1)

if __name__ == "__main__":
    main()
