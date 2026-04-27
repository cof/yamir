package com.yamir;


import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.Iterator;
import java.util.List;

import android.app.Activity;
import android.app.ActivityManager;
import android.app.ActivityManager.RunningServiceInfo;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.os.Bundle;
import android.preference.PreferenceManager;

import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;


public class YamirActivity extends Activity {
	
	private static final String INSTALLED_VERSION = "yamir.installed_version";
	private static final String DEFAULT_VERSION = "none.0";
	private static final String TAG = "YamirActivity";
	private static final String YAMIR_CONFIG = "yamir.cfg";
	private static final String YAMIR_SCRIPT = "yamir.sh";
	SharedPreferences preferences;
	
	//YamirApplication application;
	Button startButton;
	Button stopButton;
	Button settingsButton;
	TextView logText;

	File supath;
	File filesdir;
	boolean installed;
	
    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        
    	PreferenceManager.setDefaultValues(this, R.xml.preferences, false);
		preferences = PreferenceManager.getDefaultSharedPreferences(this);
       
        
        //preferences = PreferenceManager.getDefaultSharedPreferences(this);
        //String x = preferences.toString();
        
        Log.d(TAG, "Started");
        
        
        logText = (TextView) findViewById(R.id.logText);
        logText.setMovementMethod(ScrollingMovementMethod.getInstance());
        
        startButton = (Button) findViewById(R.id.startButton);
        startButton.setOnClickListener(new Button.OnClickListener() {
        	public void onClick(View v) {
        		startYamir();
            }
        });
        
        stopButton = (Button) findViewById(R.id.stopButton);
        stopButton.setOnClickListener(new Button.OnClickListener() {
        	public void onClick(View v) {
        		stopYamir();
            }
        });
        
        settingsButton = (Button) findViewById(R.id.settingsButton);
        settingsButton.setOnClickListener(new Button.OnClickListener() {
        	public void onClick(View v){
        		Intent settingsActivity = new Intent(getBaseContext(),SettingsActivity.class);
        		startActivity(settingsActivity);
        	}
        });
        
        setupPaths();
        
        installed = installFiles();
        
    }
    
    private void log(String msg) {
    	logText.append(msg + "\n");
    }
    
    private void setupPaths() {
    	
    	supath = setup_supath();
    	filesdir = getApplicationContext().getFilesDir();    	
    	log("Found " + supath.getAbsolutePath());
    	log("Found " + filesdir.getAbsolutePath());
 
    }
    
    private File setup_supath() {
        File f = new File("/system/bin/su");
        if (!f.exists()) {
            f = new File("/system/xbin/su");
            if (!f.exists()) {
            	f = null;
            }
        }
        return f;
    }
   
    
    private void startYamir() {
    	logText.setText("Starting\n");
    	if (!installed) {
    		return;
    	}
    	if (!writeConfig()) {
    		return;
    	}
    	yamir_service(true);
    }
    
    private void stopYamir()  {
    	logText.setText("Stopping\n");
    	yamir_service(false);
    }
    
    
    private String getPackageVersion() {
    	String verString;
    	try  {
    		PackageManager manager = this.getPackageManager();
    		PackageInfo info = manager.getPackageInfo(this.getPackageName(), 0);
    		verString = info.versionName + info.versionCode;
    	} catch (NameNotFoundException e) {
    		Log.e(TAG, "Package name not found", e);
    		verString = DEFAULT_VERSION;
    	}
    	return verString;
    }
    
    private boolean installFiles() {

    	String installedVersion = preferences.getString(INSTALLED_VERSION, "");
    	String packageVersion = getPackageVersion();
    	boolean force = !installedVersion.equals(packageVersion);
    	force = true;
		Log.d(TAG, "Package-version=" + packageVersion + 
				" Installed-version=" + installedVersion);
		if (!installDrivers(force)) {
			return false;
		}
		if (!installYamir(force)) {
			return false;
		}
   
    	preferences.edit().putString(INSTALLED_VERSION, packageVersion).commit();
    	Log.d(TAG, "installed " + preferences.getString(INSTALLED_VERSION, ""));
    	
    	return true;
    }

    private boolean installYamir(boolean force) {
		if (!installRawCheck(force, R.raw.yamir_sh,YAMIR_SCRIPT,"755")) {
    		return false;
    	}
		if (!installRawCheck(force, R.raw.yamird, "yamird","755")) {
    		return false;
    	}
    	if (!installRawCheck(force, R.raw.iwconfig,"iwconfig","755")) {
    		return false;
    	}
    	if (!installRawCheck(force, R.raw.killall,"killall","755")) {
    		return false;
    	}
    	return true;
    }

    private boolean installDrivers(boolean force) {
    	if (!installRawCheck(force, R.raw.none_sh,"none.sh","755")) {
    		return false;
    	}
    	if (!installRawCheck(force, R.raw.htc_desire_sh,"htc_desire.sh","755")) {
    		return false;
    	}
    	if (!installRawCheck(force, R.raw.samsung_s2_sh,"samsung_s2.sh","755")) {
    		return false;
    	}
     	if (!installRawCheck(force, R.raw.kyamir_htc_desire_ko,"kyamir_htc_desire.ko","644")) {
    		return false;
    	}
    	if (!installRawCheck(force, R.raw.kyamir_samsung_s2_ko,"kyamir_samsung_s2.ko","644")) {
    		return false;
    	}
    	return true;
    }
    
    private void addVar(StringBuilder sb, String key, String defValue) {
    	String value = preferences.getString(key, defValue);
    	sb.append("YAMIR_" + key.toUpperCase() + "=" + value + "\n"); 
    }
    
    private String genConfig() {
    	StringBuilder sb = new StringBuilder();
        addVar(sb,"device","none");
        addVar(sb,"interface","eth0");
        addVar(sb,"ssid", "yamir");
        addVar(sb,"channel","6");
        addVar(sb,"ip_addr", "192.168.1.10");
        addVar(sb,"netmask","255.255.255.0");
        return sb.toString();
    }
    
    private boolean writeConfig() {
        String config = genConfig();
        try {
        	OutputStream os =  openFileOutput(YAMIR_CONFIG, MODE_WORLD_READABLE);
            os.write(config.getBytes());
            os.close();

        } catch (IOException e) {
            return false;
        }
        return true;
    }
    
    private void yamir_service(boolean on) {
    	File script = getFileStreamPath(YAMIR_SCRIPT);
    	String mode = on ? "start" : "stop";
    	String scriptCmd = 
    			script.getAbsolutePath() + 
    			" " + mode + 
    			" " + script.getParent();
    	String[] cmdarray = {
    			supath.getAbsolutePath(), 
    			"-c", 
    			scriptCmd 
    	};
    	if (!script.exists()) {
    		log("Script not found: " + script);
    		return;
    	}
    	try {
    		log("Running " + scriptCmd);
    		Process process = Runtime.getRuntime().exec(cmdarray);
    		process.waitFor();
    		log("Done");
    		StringBuffer sb = new StringBuffer();
    		InputStreamReader isr = new InputStreamReader(process.getInputStream());
    		int ch;
    		char [] buf = new char[1024];
    		while((ch = isr.read(buf)) != -1)
    		{
    		    sb.append(buf, 0, ch);
    		}
    		log(sb.toString());
		} catch (IOException e) {
			// TODO Auto-generated catch block
		    Log.e(TAG, "exec yamir failed.",e);
		}   	
    	//startService(new Intent(this, YamirService.class));    	
    	catch (InterruptedException e) {
			// TODO Auto-generated catch block
    		Log.e(TAG, "waitfor yamir failed.",e);
		}
    	
    }
    
    private boolean installRawCheck(boolean force, int src, String dest, String mode) {
    	boolean done;
    	if (force || !getFileStreamPath(dest).exists()) {
    		done = installRaw(src,dest,mode);
    	}
    	else {
    		done = true;
    	}
    	return done;
    }
 
    private boolean installRaw(int src, String dest, String mode) {
    	InputStream is = this.getResources().openRawResource(src);
    	File file = getFileStreamPath(dest);
        byte buf[] = new byte[1024];
        int len;
        logText.append("Installing " + dest + "\n");
        try {
            OutputStream os = new FileOutputStream(file);
            while((len = is.read(buf))>0) {
                os.write(buf,0,len);
            }
            os.close();
            is.close();
        } catch (IOException e) {
            logText.append("Error installing " +dest + "\n");
            return false;
        }
        return chmod(file.getAbsolutePath(), mode);
    }
    
    public boolean chmod(String file, String mode) {
        String cmd = "chmod " + mode + " " + file;
        try {
        	Process process = Runtime.getRuntime().exec(cmd);
            if (process.waitFor() != 0) {
            	return false;
            }
        } catch (Exception e) {
            log("Error " + cmd + " " + e);
            return false; 
        } 
        return true;
    }   
    
   
    private boolean isServiceRunning(String serviceName){
        boolean serviceRunning = false;
        ActivityManager am = (ActivityManager) this.getSystemService(ACTIVITY_SERVICE);
        List<ActivityManager.RunningServiceInfo> l = am.getRunningServices(50);
        Iterator<ActivityManager.RunningServiceInfo> i = l.iterator();
        while (i.hasNext()) {
            ActivityManager.RunningServiceInfo runningServiceInfo = (ActivityManager.RunningServiceInfo) i
                    .next();

            if(runningServiceInfo.service.getClassName().equals(serviceName)){
                serviceRunning = true;
            }
        }
        return serviceRunning;
    }

    public void getAppList() {
    // Get currently running application processes	
    ActivityManager manager = (ActivityManager) getSystemService(Context.ACTIVITY_SERVICE);
    List<RunningServiceInfo> list = manager.getRunningServices(100);
    if(list != null){
    	logText.setText("");
     for(int i=0;i<list.size();++i){
        logText.append("pid=" + list.get(i).pid + " name " + list.get(i).process + "\n");
     }
    }
    }
}