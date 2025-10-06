import time
from opentelemetry import metrics
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter

# OTLP HTTP endpoint (default Alloy port with path)
OTLP_ENDPOINT = "http://localhost:4318/v1/metrics"

# Optional headers for auth/tenant routing
HEADERS = {
    # "X-Scope-OrgID": "default-tenant",
}

def main():
    # Define resource attributes (become labels in Prometheus)
    resource = Resource.create({
        "service.name": "my-python-service",
        "service.version": "1.0.0",
        "environment": "production",
    })

    # Setup OTLP exporter
    exporter = OTLPMetricExporter(
        endpoint=OTLP_ENDPOINT,
        headers=HEADERS,
    )

    # Setup reader with export interval (in milliseconds)
    reader = PeriodicExportingMetricReader(exporter, export_interval_millis=5000)

    # Setup meter provider with resource
    provider = MeterProvider(
        metric_readers=[reader],
        resource=resource,
    )
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
        counter.add(4, {"label1": "value2", "tenant_id": "default-tenant"})
        counter.add(5, {"label1": "value1", "tenant_id": "tenant1"})
        counter.add(6, {"label1": "value1", "tenant_id": "tenant2"})
        counter.add(6, {"label1": "value1"})
        print("Incremented counter")
        time.sleep(1)

if __name__ == "__main__":
    main()
