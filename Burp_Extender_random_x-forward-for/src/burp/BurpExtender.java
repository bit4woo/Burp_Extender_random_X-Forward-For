package burp;

import java.util.ArrayList;
import java.util.List;
import java.io.PrintWriter;
import java.net.URLEncoder;


public class BurpExtender implements IBurpExtender, IHttpListener
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;//现在这里定义变量，再在registerExtenderCallbacks函数中实例化，如果都在函数中就只是局部变量，不能在这实例化，因为要用到其他参数。
    
    // implement IBurpExtender
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
    	stdout = new PrintWriter(callbacks.getStdout(), true);
    	//PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true); 这种写法是定义变量和实例化，这里的变量就是新的变量而不是之前class中的全局变量了。
    	//stdout.println("testxx");
    	//System.out.println("test"); 不会输出到burp的
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName("Random_X-forward-For"); //插件名称
        callbacks.registerHttpListener(this); //如果没有注册，下面的processHttpMessage方法是不会生效的。处理请求和响应包的插件，这个应该是必要的
    }

    @Override
    public void processHttpMessage(int toolFlag,boolean messageIsRequest,IHttpRequestResponse messageInfo)
    {
    	try{
	    	if (toolFlag == 64 || toolFlag == 16 || toolFlag == 32 || toolFlag == 4){ //不同的toolflag代表了不同的burp组件 https://portswigger.net/burp/extender/api/constant-values.html#burp.IBurpExtenderCallbacks
	    		if (messageIsRequest){ //对请求包进行处理
	    			IRequestInfo analyzeRequest = helpers.analyzeRequest(messageInfo); //对消息体进行解析 
	    			String request = new String(messageInfo.getRequest());
	    			byte[] body = request.substring(analyzeRequest.getBodyOffset()).getBytes();
	    			List<String> headers = analyzeRequest.getHeaders(); //获取http请求头的信息，返回可以看作是一个python中的列表，java中是叫泛型什么的，还没弄清楚
	    			String xforward = "X-Forwarded-For: "+RandomIP.RandomIPstr();
	    			headers.add(xforward);
	    			stdout.println(xforward);
	    			byte[] new_Request = helpers.buildHttpMessage(headers,body);
	    			stdout.println(helpers.analyzeRequest(new_Request).getHeaders());
	    			messageInfo.setRequest(new_Request);//设置最终新的请求包
	    		}	    		
	    	}
    	}
    	catch(Exception e){
    		stdout.println(e);
    	}
    		
    }
}