---
layout: post
---

## 前言
CVE-2022-26533 为alist v2.0.10-v2.1.0中存在反射型XSS漏洞,使用codeql进行分析.
## 漏洞原因
```golang
r.GET("/i/:data/ipa.plist", controllers.Plist)  //绑定路由
```
```golang
//未对参数进行过滤导致XSS注入
func Plist(c *gin.Context) {
	data := c.Param("data")
	data = strings.ReplaceAll(data, "_", "/")
	data = strings.ReplaceAll(data, "-", "=")
	bytes, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		common.ErrorResp(c, err, 500)
		return
	}
	u := string(bytes)
    plist := fmt.Sprintf(`xml...%s,%s,%s...`, u, name, name)
	c.Header("Content-Type", "application/xml;charset=utf-8")
	c.Status(200)
	_, _ = c.Writer.WriteString(plist)
}
```
## 设置sink
==设置sink为 c.Writer.WriteString(plist)中的参数plist为注入点==
```golang 
class AlistSink extends DataFlow::Node {
  AlistSink() {
    exists(DataFlow::MethodCallNode m |
      m.getTarget().hasQualifiedName("github.com/gin-gonic/gin", "ResponseWriter", "WriteString")
    |
      this = m.getAnArgument()
    )
  }
}
```

## 设置source
==设置source直接使用了UntrustedFlowSource::Range==
==具体的代码可以参考: https://github.com/github/codeql/blob/main/go/ql/lib/semmle/go/frameworks/Gin.qll==
==以下是该文件的部分截取,主在是获取框架内读取数据method结果做为注入点==
```golang
  private class GithubComGinGonicGinContextSource extends UntrustedFlowSource::Range {
    GithubComGinGonicGinContextSource() {
      // Method calls:
      exists(DataFlow::MethodCallNode call, string methodName |
        call.getTarget().hasQualifiedName(packagePath(), "Context", methodName) and
        methodName in [
            "FullPath", "GetHeader", "QueryArray", "Query", "PostFormArray", "PostForm", "Param",
            "GetStringSlice", "GetString", "GetRawData", "ClientIP", "ContentType", "Cookie",
            "GetQueryArray", "GetQuery", "GetPostFormArray", "GetPostForm", "DefaultPostForm",
            "DefaultQuery", "GetPostFormMap", "GetQueryMap", "GetStringMap", "GetStringMapString",
            "GetStringMapStringSlice", "PostFormMap", "QueryMap"
          ]
      |
        this = call.getResult(0)
      )
      or
      // Field reads:
      exists(DataFlow::Field fld |
        fld.hasQualifiedName(packagePath(), "Context", ["Accepted", "Params"]) and
        this = fld.getARead()
      )
    }
  }
```
## 设置config
==source instanceof UntrustedFlowSource::Range==
```golang
class AlistConfig extends TaintTracking::Configuration {
  AlistConfig() { this = "Alist config" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof UntrustedFlowSource::Range
  }

  override predicate isSink(DataFlow::Node sink) { sink instanceof AlistSink }

  override int fieldFlowBranchLimit() { result = 5000 }
}
```
## 污点追踪
```golang
from DataFlow::PathNode source, DataFlow::PathNode sink
where exists(AlistConfig cfg | cfg.hasFlowPath(source, sink))
select source.getNode(), source, sink, "source"
```

## 完工
对codeql的学习做一点记录.