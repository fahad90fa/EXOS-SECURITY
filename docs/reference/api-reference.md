# API Reference

## Health

`GET /health`

## Mobile Analysis

`POST /api/v1/mobile/analyze`

Multipart fields:

- `file`: APK file
- `apk`: APK file

Response includes:

- `status`
- `risk_score`
- `report`
