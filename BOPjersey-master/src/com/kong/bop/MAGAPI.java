package com.kong.bop;

import java.net.URI;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

public class MAGAPI {
  public static void main(String[] args) {
    HttpClient httpclient = HttpClients.createDefault();

    try {
      String expr = "Id=2140251882&count=10000&attributes=Id,AA.AuId,AA.AfId";
      URIBuilder builder =
          new URIBuilder("https://oxfordhk.azure-api.net/academic/v1.0/evaluate?expr=" + expr
              + "&subscription-key=f7cc29509a8443c5b3a5e56b0e38b5a6");
      URI uri = builder.build();
      HttpGet request = new HttpGet(uri);

      HttpResponse response = httpclient.execute(request);
      HttpEntity entity = response.getEntity();

      if (entity != null) {
        System.out.println(EntityUtils.toString(entity));
      }
    } catch (Exception e) {
      System.out.println(e.getMessage());
    }
  }

  public static String Get(HttpClient httpclient, String expr) {
    // System.out.println(expr);
    try {
      URIBuilder builder =
          new URIBuilder("https://oxfordhk.azure-api.net/academic/v1.0/evaluate?expr=" + expr
              + "&subscription-key=f7cc29509a8443c5b3a5e56b0e38b5a6");
      URI uri = builder.build();
      HttpGet request = new HttpGet(uri);
      HttpResponse response = httpclient.execute(request);
      HttpEntity entity = response.getEntity();
      return EntityUtils.toString(entity);
    } catch (Exception e) {
      System.out.println(e.getMessage());
      return null;
    }
  }
}
