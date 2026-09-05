import { errorHandling, telemetryData, checkDatabaseConfig } from '../utils/middleware';

// CORS 跨域响应头
const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
};

// R2 仅作为 Telegram 图片的临时镜像缓存，避免给大文件请求带来额外内存压力
const R2_MIRROR_MAX_BYTES = 50 * 1024 * 1024;

// OPTIONS 预检请求处理
async function handleOptions(context) {
    if (context.request.method === 'OPTIONS') {
        return new Response(null, {
            status: 204,
            headers: corsHeaders
        });
    }
    return context.next();
}

// Telegram 上传成功后，异步把图片镜像到 R2。
// 没有绑定 img_r2 时直接跳过，原有上传逻辑不受影响。
async function mirrorTelegramUploadToR2(context) {
    const { request, env, waitUntil } = context;

    if (request.method !== 'POST' || !env.img_r2) {
        return context.next();
    }

    const url = new URL(request.url);
    const uploadChannel = (url.searchParams.get('uploadChannel') || 'telegram').toLowerCase();

    // 只镜像 Telegram；R2/S3/Discord 等其他渠道保持原逻辑。
    if (uploadChannel !== 'telegram') {
        return context.next();
    }

    // 客户端分片接口里的 file 只是单个分片，不能当成完整文件镜像。
    if (
        url.searchParams.get('chunked') === 'true' ||
        url.searchParams.get('initChunked') === 'true' ||
        url.searchParams.get('merge') === 'true' ||
        url.searchParams.get('cleanup') === 'true'
    ) {
        return context.next();
    }

    const contentLength = Number(request.headers.get('content-length') || 0);
    if (contentLength > R2_MIRROR_MAX_BYTES) {
        return context.next();
    }

    // clone 后交给原上传逻辑处理；只有 Telegram 上传成功才会写 R2。
    const requestClone = request.clone();
    const response = await context.next();

    if (!response.ok) {
        return response;
    }

    try {
        const payload = await response.clone().json();
        const src = Array.isArray(payload) ? payload[0]?.src : null;
        if (!src) {
            return response;
        }

        const fileUrl = new URL(src, url.origin);
        const filePrefix = '/file/';
        if (!fileUrl.pathname.startsWith(filePrefix)) {
            return response;
        }

        const fullId = decodeURIComponent(fileUrl.pathname.slice(filePrefix.length));
        if (!fullId) {
            return response;
        }

        const formData = await requestClone.formData();
        const file = formData.get('file');
        if (!file || typeof file.size !== 'number' || typeof file.type !== 'string') {
            return response;
        }

        // 只做图片镜像；项目本身仍可正常托管其他类型文件。
        if (!file.type.startsWith('image/') || file.size > R2_MIRROR_MAX_BYTES) {
            return response;
        }

        waitUntil(
            env.img_r2.put(fullId, file, {
                httpMetadata: {
                    contentType: file.type || 'application/octet-stream'
                }
            }).catch(error => {
                console.warn(`R2 mirror upload failed for ${fullId}:`, error.message);
            })
        );
    } catch (error) {
        // 镜像失败不能影响 Telegram 主存储上传成功结果。
        console.warn('R2 mirror middleware skipped:', error.message);
    }

    return response;
}

export const onRequest = [
    checkDatabaseConfig,
    handleOptions,
    errorHandling,
    telemetryData,
    mirrorTelegramUploadToR2
];