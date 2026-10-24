package org.actscope.f1fixture;

import android.app.Activity;
import android.graphics.Color;
import android.os.Bundle;
import android.view.Gravity;
import android.widget.LinearLayout;
import android.widget.TextView;

/** A passive visual fixture: no permissions, network, background work or file access. */
public final class MainActivity extends Activity {
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        boolean original = "A".equals(BuildConfig.ROLE);
        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setGravity(Gravity.CENTER);
        page.setPadding(40, 40, 40, 40);
        page.setBackgroundColor(original ? Color.rgb(232, 242, 255) : Color.rgb(255, 236, 221));
        text(page, "ACTScope · F1", 24);
        text(page, BuildConfig.ROLE, 100);
        text(page, original ? "原始版本 / Original" : "替换版本 / Replacement", 26);
        text(page, BuildConfig.FIXTURE_ID + "\n" + BuildConfig.VERSION_NAME, 18);
        text(page, "本应用仅显示测试身份，不申请权限、不联网。\n"
            + "请将当前画面与本轮平台安装任务一起记录。\n"
            + "单独看到 B 不代表已证明安装劫持。", 16);
        setContentView(page);
    }

    private void text(LinearLayout page, String value, int size) {
        TextView item = new TextView(this);
        item.setText(value);
        item.setTextSize(size);
        item.setTextColor(Color.rgb(25, 38, 55));
        item.setGravity(Gravity.CENTER);
        item.setPadding(0, 16, 0, 16);
        page.addView(item);
    }
}
