import { checkDatabaseConfig } from '../utils/middleware';
import { fetchSecurityConfig } from '../utils/sysConfig';
import { getDatabase } from '../utils/databaseAdapter.js';
import {
    FILE_CACHE_CONTROL,
    handleHeadRequest,
    isDomainAllowed,
    isTgChannel,
    returnWithCheck,
    setCommonHeaders,
} from './fileTools';

const R2_MIRROR_MAX_BYTES = 50 * 1024 * 1024;

function decodeFileId(params) {
    try {
        let rawPath = params?.path || '';
        if (Array.isArray(rawPath)) {
            rawPath = rawPath.join('/');
        }
        return decodeURIComponent(rawPath).split(',').join('/');
    } catch (error) {
        return '';
    }
}

function buildPublicAccessContext(context, securityConfig, url) {
    return {
        ...context,
        url,
        Referer: context.request.headers.get('Referer'),
        securityConfig,
        fileAccess: {
            isAdminPreview: false,
            adminAuthResult: { authorized: false, authType: null },
            cacheControl: undefined,
        },
    };
}

async function readR2Mirror(context, fileId, encodedFileName, fileType) {
    const { request, env } = context;
    const range = request.headers.get('Range');

    try {
        let object;

        if (range) {
            const matches = range.match(/bytes=(\d+)-(\d*)/);
            if (matches) {
                const start = parseInt(matches[1]);
                const end = matches[2] ? parseInt(matches[2]) : undefined;
                const options = { range: { offset: start } };
                if (end !== undefined) {
                    options.range.length = end - start + 1;
                }
                object = await env.img_r2.get(fileId, options);
            } else {
                object = await env.img_r2.get(fileId);
            }
        } else {
            object = await env.img_r2.get(fileId);
        }

        if (!object) {
            return null;
        }

        const headers = new Headers();
        object.writeHttpMetadata(headers);
        setCommonHeaders(headers, encodedFileName, fileType, FILE_CACHE_CONTROL.PUBLIC);
        headers.set('X-ImgBed-Source', 'R2-Mirror');

        if (object.httpEtag) {
            headers.set('ETag', object.httpEtag);
        }

        if (request.method === 'HEAD') {
            if (object.size !== undefined) {
                headers.set('Content-Length', object.size.toString());
            }
            return handleHeadRequest(headers, object.httpEtag || null);
        }

        if (range && object.range) {
            const rangeStart = object.range.offset;
            const rangeEnd = rangeStart + object.range.length - 1;
            headers.set('Content-Range', `bytes ${rangeStart}-${rangeEnd}/${object.size}`);
            headers.set('Content-Length', object.range.length.toString());

            return new Response(object.body, {
                status: 206,
                headers,
            });
        }

        if (object.size !== undefined) {
            headers.set('Content-Length', object.size.toString());
        }

        return new Response(object.body, {
            status: 200,
            headers,
        });
    } catch (error) {
        console.warn(`R2 mirror read failed for ${fileId}:`, error.message);
        return null;
    }
}

async function getEdgeCache() {
    try {
        if (typeof caches !== 'undefined' && caches.default) {
            return caches.default;
        }
    } catch (error) {
        console.warn('Cloudflare edge cache unavailable:', error.message);
    }
    return null;
}

function cacheResponse(context, cache, cacheKey, response) {
    if (!cache || !response || response.status !== 200) {
        return;
    }

    context.waitUntil(
        cache.put(cacheKey, response.clone()).catch(error => {
            console.warn('Edge cache write failed:', error.message);
        })
    );
}

function warmR2FromTelegram(context, fileId, imgRecord, response) {
    if (!context.env.img_r2 || !response || response.status !== 200) {
        return;
    }

    const fileType = imgRecord.metadata?.FileType || response.headers.get('Content-Type') || '';
    const fileSizeBytes = Number(imgRecord.metadata?.FileSizeBytes || 0);

    if (!fileType.startsWith('image/')) {
        return;
    }

    // 旧记录若没有可靠的字节大小，不主动整文件读入内存；新上传会由 upload middleware 预热。
    if (!fileSizeBytes || fileSizeBytes > R2_MIRROR_MAX_BYTES) {
        return;
    }

    const responseClone = response.clone();
    context.waitUntil((async () => {
        try {
            const body = await responseClone.arrayBuffer();
            if (body.byteLength > R2_MIRROR_MAX_BYTES) {
                return;
            }
            await context.env.img_r2.put(fileId, body, {
                httpMetadata: {
                    contentType: fileType || 'application/octet-stream'
                }
            });
        } catch (error) {
            console.warn(`R2 read-through warm failed for ${fileId}:`, error.message);
        }
    })());
}

// Telegram 图片读取顺序：Cloudflare 边缘缓存 -> R2 临时镜像 -> Telegram 原存储。
async function telegramR2MirrorCache(context) {
    const { request, env, params } = context;

    if (!env.img_r2 || (request.method !== 'GET' && request.method !== 'HEAD')) {
        return context.next();
    }

    const url = new URL(request.url);

    // 管理后台预览具有独立鉴权/缓存策略，继续交给原处理器。
    if (url.searchParams.get('from') === 'admin') {
        return context.next();
    }

    const fileId = decodeFileId(params);
    if (!fileId) {
        return context.next();
    }

    try {
        const securityConfig = await fetchSecurityConfig(env);
        const accessContext = buildPublicAccessContext(context, securityConfig, url);

        // 防盗链、黑白名单、内容审核等规则仍沿用项目原逻辑，不能因为 R2 命中而绕过。
        if (!isDomainAllowed(accessContext)) {
            return context.next();
        }

        const db = getDatabase(env);
        const imgRecord = await db.getWithMetadata(fileId);

        if (!imgRecord || !isTgChannel(imgRecord)) {
            return context.next();
        }

        const accessResult = await returnWithCheck(accessContext, imgRecord);
        if (accessResult.status !== 200) {
            return context.next();
        }

        const fileName = imgRecord.metadata?.FileName || fileId;
        const encodedFileName = encodeURIComponent(fileName);
        const fileType = imgRecord.metadata?.FileType || null;
        const range = request.headers.get('Range');

        // Range/HEAD 不放入 Cache API，避免不同范围互相污染。
        const canUseEdgeCache = request.method === 'GET' && !range && !request.headers.get('Authorization');
        const cache = canUseEdgeCache ? await getEdgeCache() : null;
        const cacheKey = canUseEdgeCache ? new Request(url.toString(), { method: 'GET' }) : null;

        if (cache && cacheKey) {
            const cached = await cache.match(cacheKey);
            if (cached) {
                const headers = new Headers(cached.headers);
                headers.set('X-ImgBed-Source', 'Edge-Cache');
                return new Response(cached.body, {
                    status: cached.status,
                    statusText: cached.statusText,
                    headers,
                });
            }
        }

        const r2Response = await readR2Mirror(accessContext, fileId, encodedFileName, fileType);
        if (r2Response) {
            if (cache && cacheKey && r2Response.status === 200) {
                cacheResponse(context, cache, cacheKey, r2Response);
            }
            return r2Response;
        }

        // R2 已被生命周期规则清理或尚未预热：回退 Telegram，并重新填充边缘缓存/R2。
        const telegramResponse = await context.next();
        if (telegramResponse.ok && telegramResponse.status === 200) {
            if (cache && cacheKey) {
                cacheResponse(context, cache, cacheKey, telegramResponse);
            }
            warmR2FromTelegram(context, fileId, imgRecord, telegramResponse);
        }

        return telegramResponse;
    } catch (error) {
        // 缓存层任何异常都不能影响原图床可用性。
        console.warn('Telegram R2 mirror middleware fallback:', error.message);
        return context.next();
    }
}

export const onRequest = [checkDatabaseConfig, telegramR2MirrorCache];