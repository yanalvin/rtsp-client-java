package com.alvin.rtsp;

import com.alvin.utils.DigestUtils;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.codec.http.*;
import io.netty.handler.codec.rtsp.RtspHeaderNames;
import io.netty.handler.codec.rtsp.RtspMethods;
import io.netty.handler.codec.rtsp.RtspResponseStatuses;
import io.netty.handler.codec.rtsp.RtspVersions;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * Created by alvin on 2020/9/28.
 */
public class RTSPHandler extends ChannelInboundHandlerAdapter {

    private final static Logger LOGGER = LoggerFactory.getLogger(RTSPHandler.class);

    private final static String WWW_AUTHENTICATE_RTSP = "WWW-Authenticate";
    private final static String BASIC_AUTHENTICATE_RTSP = "Basic";
    private final static String DIGEST_AUTHENTICATE_RTSP = "Digest";

    private int cseq = 1;

    private String uri;
    private String username;
    private String password;

    private int conentLength = 0;
    private StringBuilder sdp = new StringBuilder("\n");
    private boolean hasAuth = false;
    private HttpMethod currentMethod = RtspMethods.OPTIONS;

    public RTSPHandler(String uri, String username, String password) {
        this.uri = uri;
        this.username = username;
        this.password = password;
    }

    @Override
    public void channelActive(final ChannelHandlerContext ctx) {
        LOGGER.debug("channelActive: {}", ctx);
        FullHttpRequest request = this.options(null);
        ctx.writeAndFlush(request);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        LOGGER.info("exceptionCaught: {}", cause);
        ctx.close();
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (msg instanceof DefaultHttpResponse) {
            DefaultHttpResponse res = (DefaultHttpResponse) msg;
            if (RtspResponseStatuses.OK.equals(res.status())) {
                if (res.headers().contains(RtspHeaderNames.PUBLIC)) {
                    LOGGER.debug("OPTIONS Reply: {}", res.toString());
                    ctx.writeAndFlush(this.describe(null));
                } else if (res.headers().contains(RtspHeaderNames.CONTENT_LENGTH)) {
                    this.conentLength = res.headers().getInt(RtspHeaderNames.CONTENT_LENGTH);
                    LOGGER.debug(res.toString());
                } else {
                    LOGGER.warn("Other Reply: {}", res.toString());
                }
            } else if (RtspResponseStatuses.UNAUTHORIZED.equals(res.status())) {
                if (hasAuth) {
                    LOGGER.warn("Authentication Failed");
                    ctx.close();
                    return;
                }
                Map<String, String> authMap = new HashMap<>(10);
                LOGGER.debug(res.toString());
                HttpHeaders httpHeaders = res.headers();
                for (Map.Entry entry : httpHeaders.entries()) {
                    if (WWW_AUTHENTICATE_RTSP.equals(entry.getKey())) {
                        String value = (String) entry.getValue();
                        if (value.startsWith(DIGEST_AUTHENTICATE_RTSP)) {
                            authMap.put(DIGEST_AUTHENTICATE_RTSP, value);
                        } else if (value.startsWith(BASIC_AUTHENTICATE_RTSP)) {
                            authMap.put(BASIC_AUTHENTICATE_RTSP, "");
                        }
                    }
                }
                if (authMap.containsKey(DIGEST_AUTHENTICATE_RTSP)) {
                    /**
                     *  digest authentication
                     */
                    String value = authMap.get(DIGEST_AUTHENTICATE_RTSP);
                    String realm = "";
                    String nonce = "";
                    String content = value.replaceFirst(DIGEST_AUTHENTICATE_RTSP, "");
                    String[] arrs = content.split(",");
                    for (String volumn : arrs) {
                        volumn = volumn.trim();
                        if (volumn.startsWith("nonce")) {
                            String nonceSrc = volumn.split("=")[1];
                            if (nonceSrc.contains("\"")) {
                                nonce = nonceSrc.substring(1, nonceSrc.length() - 1);
                            }
                        } else if (volumn.startsWith("realm")) {
                            String realmSrc = volumn.split("=")[1];
                            if (realmSrc.contains("\"")) {
                                realm = realmSrc.substring(1, realmSrc.length() - 1);
                            }
                        }
                    }
                    //response=md5(md5(username:realm:password):nonce:md5(public_method:url))
                    String response = null;
                    if (RtspMethods.OPTIONS.equals(this.currentMethod)) {
                        response = DigestUtils.md5sums(DigestUtils.md5sums(this.username + ":" + realm + ":" + this.password) +
                                ":" + nonce + ":" + DigestUtils.md5sums(RtspMethods.OPTIONS + ":" + this.uri));
                    } else if (RtspMethods.DESCRIBE.equals(this.currentMethod)) {
                        response = DigestUtils.md5sums(DigestUtils.md5sums(this.username + ":" + realm + ":" + this.password) +
                                ":" + nonce + ":" + DigestUtils.md5sums(RtspMethods.DESCRIBE + ":" + this.uri));
                    }
                    StringBuilder sBuilder = new StringBuilder();
                    sBuilder.append(DIGEST_AUTHENTICATE_RTSP);
                    sBuilder.append(" ");
                    sBuilder.append("username=\"");
                    sBuilder.append(this.username);
                    sBuilder.append("\", ");
                    sBuilder.append("realm=\"");
                    sBuilder.append(realm);
                    sBuilder.append("\", ");
                    sBuilder.append("nonce=\"");
                    sBuilder.append(nonce);
                    sBuilder.append("\", ");
                    sBuilder.append("uri=\"");
                    sBuilder.append(this.uri);
                    sBuilder.append("\"");
                    sBuilder.append(", ");
                    sBuilder.append("response=\"");
                    sBuilder.append(response);
                    sBuilder.append("\"");
                    if (RtspMethods.OPTIONS.equals(this.currentMethod)) {
                        FullHttpRequest fullHttpRequest = this.options(sBuilder.toString());
                        ctx.writeAndFlush(fullHttpRequest);
                    } else if (RtspMethods.DESCRIBE.equals(this.currentMethod)) {
                        FullHttpRequest fullHttpRequest = this.describe(sBuilder.toString());
                        ctx.writeAndFlush(fullHttpRequest);
                    }
                    hasAuth = true;
                }
                if (authMap.containsKey(BASIC_AUTHENTICATE_RTSP) && !hasAuth) {
                    /**
                     * basic authentication
                     */
                    String authorization = DigestUtils.encodeBase64(this.username + ":" + this.password);
                    authorization = BASIC_AUTHENTICATE_RTSP + " " + authorization;
                    FullHttpRequest fullHttpRequest = this.describe(authorization);
                    ctx.writeAndFlush(fullHttpRequest);
                    hasAuth = true;
                }
            } else {
                LOGGER.info(res.toString());
                ctx.close();
            }
        } else if (msg instanceof DefaultHttpContent) {
            DefaultHttpContent content = (DefaultHttpContent) msg;
            ByteBuf byteBuf = content.content();
            if (!byteBuf.hasArray()) {
                int len = byteBuf.readableBytes();
                this.conentLength = this.conentLength - len;

                byte[] bytes = new byte[len];
                byteBuf.getBytes(byteBuf.readerIndex(), bytes);
                String sdp = new String(bytes);
                this.sdp.append(sdp);
            }
            if (this.conentLength <= 0) {
                this.parseSdp(sdp.toString());
                ctx.close();
            }
        } else {
            LOGGER.debug("dataType error: {}", msg.getClass().getTypeName());
        }
    }

    private FullHttpRequest options(String authorization) {
        FullHttpRequest request = new DefaultFullHttpRequest(
                RtspVersions.RTSP_1_0, RtspMethods.OPTIONS, uri);
        request.headers()
                .set(RtspHeaderNames.CSEQ, ++cseq);
        if (StringUtils.isNotBlank(authorization)) {
            request.headers().set("Authorization", authorization);
        }
        LOGGER.debug("OPTION Request: {}", request.toString());
        return request;
    }

    private FullHttpRequest describe(String authorization) {
        FullHttpRequest request = new DefaultFullHttpRequest(
                RtspVersions.RTSP_1_0, RtspMethods.DESCRIBE, uri);
        request.headers()
                .set(RtspHeaderNames.CSEQ, ++cseq)
                .set(RtspHeaderNames.ACCEPT, "application/sdp");
        if (StringUtils.isNotBlank(authorization)) {
            request.headers().set("Authorization", authorization);
        }
        this.currentMethod = RtspMethods.DESCRIBE;
        LOGGER.debug(request.toString());
        return request;
    }

    private void parseSdp(String sdp) {
        LOGGER.debug(sdp);
        Map<String, List<String>> mediaMap = new HashMap<>(10);
        String[] array = sdp.split("\\n");
        String mediaName = "";
        for (int i = 0; i < array.length; i++) {
            String line = array[i];
            if (line.startsWith("m=")) {
                mediaName = line.substring(line.indexOf("=") + 1, line.indexOf(" "));
                if (mediaName.equals("video") || mediaName.equals("audio")) {
                    mediaMap.put(mediaName, new ArrayList<>());
                } else {
                    mediaName = "";
                }
            } else if (StringUtils.isNotBlank(mediaName)) {
                if (line.startsWith("b=") || line.startsWith("a=")) {
                    List<String> medialist = mediaMap.get(mediaName);
                    medialist.add(line);
                }
            }
        }
        for (String mediaKey : mediaMap.keySet()) {
            StringBuilder stringBuilder = new StringBuilder();
            List<String> mediaInfo = mediaMap.get(mediaKey);
            mediaInfo.forEach((s) -> {
                stringBuilder.append("\n");
                stringBuilder.append(s);
            });
            LOGGER.info("\n[>>>>> {} <<<<<] {}", mediaKey, stringBuilder.toString());
        }
    }

}