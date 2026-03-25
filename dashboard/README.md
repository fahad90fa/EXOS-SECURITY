# Dashboard Components

This folder contains reusable visualization and marketplace widgets for the Nexus Sentinel dashboard.

## Included Components

- `graphs/` - attack surface, attack path, vulnerability heatmap, and topology views
- `charts/` - trend, compliance, and risk visualizations
- `interactive/` - code editor, traffic viewer, and payload testing panels
- `Marketplace/` - plugin discovery, install, settings, details, and developer tools

## Usage

Import from `dashboard/components/index.ts` when wiring these widgets into a Vue or React host.

The Vue single-file components are intentionally dependency-light and render with native SVG and form controls so they can be embedded in the desktop UI or a future web dashboard without requiring a charting runtime.
