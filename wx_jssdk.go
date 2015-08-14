//微信公众号jssdk
package libs

import(
	"XYAPIServer/XYLibs"
	"fmt"
	"errors"
	"encoding/json"
	"math/rand"
	"time"
	"net/http"
	"crypto/sha1"
	"strings"
)

const (
	wx_mp_cache_key_token = "wx_mp_cache_key_token"
	wx_mp_cache_key_ticket = "wx_mp_cache_key_ticket"
	wx_mp_token_url = "https://api.weixin.qq.com/cgi-bin/token"
	wx_mp_ticket_url = "https://api.weixin.qq.com/cgi-bin/ticket/getticket"
)

func NewWXMPjsSdk(appid,secret string,redis *XYLibs.RedisHash) *WXMPjsSdk {
	obj := &WXMPjsSdk{
		appId:appid,
		appSecret:secret,
		redisDB:redis,
	}
	return obj
}

type WXMPjsSdk struct {
	appId string
	appSecret string
	redisDB *XYLibs.RedisHash
}

func (wx *WXMPjsSdk) GetAccessToken()(string,error) {
	accountToken,_ := wx.redisDB.Get(wx_mp_cache_key_token)
	if accountToken != nil {
		token :=""
		switch accountToken.(type) {
			case string :
				token = accountToken.(string)
			case []uint8:
				token = string(accountToken.([]uint8))
		}
		if token != "" {
			return token,nil
		}
		return "",errors.New("get cache token  fail")	
	}else{
		url := fmt.Sprintf("%s?grant_type=client_credential&appid=%s&secret=%s",wx_mp_token_url,wx.appId,wx.appSecret)
		data ,err := XYLibs.HttpGet(url)
		if err != nil {
			return "",err
		}
		var res map[string]interface{}
		e := json.Unmarshal(data,&res)
		if e != nil {
			return "",e
		}
		if tmp,ok := res["access_token"];ok {
			if token,ok := tmp.(string);ok{
				exp := 0
				switch res["expires_in"].(type) {
					case float64:
						exp = int(res["expires_in"].(float64))
					case int64:
						exp = int(res["expires_in"].(int64))
				}
				if exp > 200 {
					wx.redisDB.SETEX(wx_mp_cache_key_token,exp - 200,token)
				
				}
				return token,nil
			}
			return "",errors.New("read access_token fail")
		}
		return "",errors.New(res["errmsg"].(string))
	}
	
}


func  (wx *WXMPjsSdk) GetJsApiTicket()(string,error){
	jsapiTicket,_ := wx.redisDB.Get(wx_mp_cache_key_ticket)
	//fmt.Printf("%#v\n",jsapiTicket)
	if jsapiTicket != nil {
		ticket := ""
		switch jsapiTicket.(type) {
			case string:
			ticket = jsapiTicket.(string)
			case []uint8:
			ticket = string(jsapiTicket.([]uint8))
		}
		if ticket != "" {
			return ticket , nil
		}
		return "",errors.New("read cache ticket fail")
	}else{
		token,err := wx.GetAccessToken()
		if err != nil {
			return "",err
		}
		url := fmt.Sprintf("%s?type=jsapi&access_token=%s",wx_mp_ticket_url,token)
		println(url)
		data ,err := XYLibs.HttpGet(url)
		if err != nil {
			return "",err
		}
		var res map[string]interface{}
		e := json.Unmarshal(data,&res)
		if e != nil {
			return "",e
		}
		if tmp,ok := res["ticket"];ok {
			ticket := tmp.(string)
			exp := 0
			switch res["expires_in"].(type) {
					case float64:
						exp = int(res["expires_in"].(float64))
					case int64:
						exp = int(res["expires_in"].(int64))
			}
			if exp > 200 {
					wx.redisDB.SETEX(wx_mp_cache_key_ticket,exp - 200,ticket)	
			}
			return ticket,nil
			
		}
		return "",errors.New(res["errmsg"].(string))
	}
}

func (wx *WXMPjsSdk) CreateNonceStr() string {
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    str := "";
	rd := rand.New(rand.NewSource(time.Now().UnixNano()))
	length := len(chars) - 1
    for i := 0; i < 16; i++ {
		index := rd.Intn(length)
		str += string(chars[index])
    }
    return str;
}

func (wx *WXMPjsSdk) GetSignPackage(req *http.Request) map[string]string {
	res := map[string]string{
		  "appId"   : "",
	      "nonceStr"  : "",
	      "timestamp" : "",
	      "url"       : "",
	      "signature" : "",
	      "rawString" : "",
	}
	ua := req.Header.Get("User-Agent")
	if ua != "" {
		ua = strings.ToLower(ua)
	}
	//println(ua)
	if !strings.Contains(ua,"micromessenger") {
		return res
	}
	scheme := req.URL.Scheme
	if scheme == "" {
		if req.TLS == nil {
			scheme = "http"
		}else{
			scheme = "https"
		}	
	}
	jsapiTicket,err := wx.GetJsApiTicket()
	if err != nil {
		println(err.Error())
	}
	res["appId"] = wx.appId
	res["url"] = fmt.Sprintf("%s://%s%s",scheme,req.Host,req.URL.RequestURI())
	res["timestamp"] =  fmt.Sprintf("%d",time.Now().Unix())
    res["nonceStr"] = wx.CreateNonceStr()
	res["rawString"] = fmt.Sprintf("jsapi_ticket=%s&noncestr=%s&timestamp=%s&url=%s",jsapiTicket,res["nonceStr"],res["timestamp"],res["url"])
    println(res["rawString"])
	res["signature"] = fmt.Sprintf("%x",sha1.Sum([]byte(res["rawString"])))
	println(res["signature"])
	return res
}