import { Hono } from 'hono';
import {
  handleGetAuthorizedDevices,
  handleGetDevice,
  handleGetDevices,
  handleGetDeviceByIdentifier,
  handleUpdateDeviceKeys,
  handleUpdateDeviceTrust,
  handleUntrustDevices,
  handleRetrieveDeviceKeys,
  handleDeactivateDevice,
  handleRevokeAllTrustedDevices,
  handleRevokeTrustedDevice,
  handleTrustDevicePermanently,
  handleDeleteAllDevices,
  handleDeleteDevice,
  handleUpdateDeviceName,
  handleUpdateDeviceToken,
  handleUpdateDeviceWebPushAuth,
  handleRegisterDevice,
  handleReportLostTrust,
} from './handlers/devices';
import type { AppEnv } from './router';

// Older clients call the device endpoints without the /api prefix.
const devices = <Suffix extends string>(suffix: Suffix): [`/api/devices${Suffix}`, `/devices${Suffix}`] => [`/api/devices${suffix}`, `/devices${suffix}`];

export const deviceRoutes = new Hono<AppEnv>();

deviceRoutes.on('GET', devices(''), (c) => handleGetDevices(c.req.raw, c.env, c.get('userId')));
deviceRoutes.on('POST', devices(''), (c) => handleRegisterDevice(c.req.raw, c.env, c.get('userId')));
deviceRoutes.on('DELETE', devices(''), (c) => handleDeleteAllDevices(c.req.raw, c.env, c.get('userId')));
deviceRoutes.on('POST', devices('/lost-trust'), (c) => handleReportLostTrust(c.req.raw, c.env, c.get('userId')));
deviceRoutes.on('GET', devices('/authorized'), (c) => handleGetAuthorizedDevices(c.req.raw, c.env, c.get('userId')));
deviceRoutes.on('DELETE', devices('/authorized'), (c) => handleRevokeAllTrustedDevices(c.req.raw, c.env, c.get('userId')));
deviceRoutes.on('DELETE', devices('/authorized/:deviceId'), (c) => handleRevokeTrustedDevice(c.req.raw, c.env, c.get('userId'), c.req.param('deviceId')));
deviceRoutes.on('POST', devices('/authorized/:deviceId/permanent'), (c) => handleTrustDevicePermanently(c.req.raw, c.env, c.get('userId'), c.req.param('deviceId')));
deviceRoutes.on('GET', devices('/:deviceId'), (c) => handleGetDevice(c.req.raw, c.env, c.get('userId'), c.req.param('deviceId')));
deviceRoutes.on('DELETE', devices('/:deviceId'), (c) => handleDeleteDevice(c.req.raw, c.env, c.get('userId'), c.req.param('deviceId')));
deviceRoutes.on('PUT', devices('/:deviceId/name'), (c) => handleUpdateDeviceName(c.req.raw, c.env, c.get('userId'), c.req.param('deviceId')));
deviceRoutes.on('GET', devices('/identifier/:deviceId'), (c) => handleGetDeviceByIdentifier(c.req.raw, c.env, c.get('userId'), c.req.param('deviceId')));
deviceRoutes.on(['PUT', 'POST'], [...devices('/:deviceId/keys'), ...devices('/identifier/:deviceId/keys')], (c) => handleUpdateDeviceKeys(c.req.raw, c.env, c.get('userId'), c.req.param('deviceId')));
deviceRoutes.on(['PUT', 'POST'], devices('/identifier/:deviceId/token'), (c) => handleUpdateDeviceToken(c.req.raw, c.env, c.get('userId'), c.req.param('deviceId')));
deviceRoutes.on(['PUT', 'POST'], devices('/identifier/:deviceId/web-push-auth'), (c) => handleUpdateDeviceWebPushAuth(c.req.raw, c.env, c.get('userId'), c.req.param('deviceId')));
deviceRoutes.on('POST', devices('/:deviceId/retrieve-keys'), (c) => handleRetrieveDeviceKeys(c.req.raw, c.env, c.get('userId'), c.req.param('deviceId')));
deviceRoutes.on(['POST', 'DELETE'], devices('/:deviceId/deactivate'), (c) => handleDeactivateDevice(c.req.raw, c.env, c.get('userId'), c.req.param('deviceId')));
deviceRoutes.on('POST', devices('/update-trust'), (c) => handleUpdateDeviceTrust(c.req.raw, c.env, c.get('userId')));
deviceRoutes.on('POST', devices('/untrust'), (c) => handleUntrustDevices(c.req.raw, c.env, c.get('userId')));
