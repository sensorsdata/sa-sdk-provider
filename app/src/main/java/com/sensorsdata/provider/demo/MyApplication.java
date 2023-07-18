package com.sensorsdata.provider.demo;

import android.app.Application;
import android.util.Log;

import com.sensorsdata.analytics.android.sdk.SAConfigOptions;
import com.sensorsdata.analytics.android.sdk.SensorsAnalyticsAutoTrackEventType;
import com.sensorsdata.analytics.android.sdk.SensorsDataAPI;
import com.sensorsdata.encrypt.plugin.SASMEncryptor;

public class MyApplication extends Application {
    @Override
    public void onCreate() {
        super.onCreate();
        initSensorsDataAPI();
    }

    private void initSensorsDataAPI() {
        SAConfigOptions configOptions = new SAConfigOptions("http://10.129.20.62:8106/sa?project=dengshiwei");
        // 打开自动采集, 并指定追踪哪些 AutoTrack 事件
        configOptions.setAutoTrackEventType(SensorsAnalyticsAutoTrackEventType.APP_START |
                        SensorsAnalyticsAutoTrackEventType.APP_END |
                        SensorsAnalyticsAutoTrackEventType.APP_VIEW_SCREEN |
                        SensorsAnalyticsAutoTrackEventType.APP_CLICK)
                .enableTrackAppCrash()
                .enableJavaScriptBridge(true)
                .enableSaveDeepLinkInfo(true)
                .enableAutoAddChannelCallbackEvent(true)
                .enableVisualizedProperties(true)
                .enableEncrypt(true)
                .enableLog(true)
                .registerEncryptor(new SASMEncryptor())
                .enableVisualizedAutoTrack(true);
        SensorsDataAPI.startWithConfigOptions(this, configOptions);
        SensorsDataAPI.sharedInstance(this).trackFragmentAppViewScreen();
        SensorsDataAPI.sharedInstance().trackAppInstall();
        Log.d("SA.Preset", SensorsDataAPI.sharedInstance().getPresetProperties().toString());
    }
}
