package com.kong.bop;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClients;
import org.json.JSONArray;
import org.json.JSONObject;

public class IdId {
  private static int reqNum = 0;

  public static void main(String[] args) {
    HttpClient httpclient = HttpClients.createDefault();
    // 2140251882, 2140251883 // 2126125555, 2153635508L//1970381522, 2162351023L // 2125894967L,
    // 1970033396L // 2292217923L, 2100837269 // 2151561903L, 2015720094
    // 2146007994, 2100837269跑不出来 //2332023333L,2100470808
    // 2147152072L, 189831743
    reqNum = 0;
    long start = System.currentTimeMillis();
    List<List<Long>> result = Calculate(httpclient, 2126125555, 2153635508L);// 2088608143,
                                                                             // 2058000726);
    long end = System.currentTimeMillis();
    // System.out.println(result.size() + " paths in " + (end - start) / 1000 + " s:");
    System.out.println(result.size() + " paths in " + (end - start) + " ms:");
    System.out.println(reqNum + " requests to MAG API");
    // System.out.println(result.toString());
  }

  public static List<List<Long>> Calculate(HttpClient httpclient, long Id1, long Id2) {
    List<List<Long>> result = new ArrayList<List<Long>>();

    String expr =
        "Or(Id=" + Id1 + ",Id=" + Id2 + ")&count=10000&attributes=Id,RId,F.FId,J.JId,C.CId,AA.AuId";
    JSONObject json = SendRequset(httpclient, expr);
    JSONArray entities = json.optJSONArray("entities");
    if (entities == null || entities.length() == 0) return result;
    JSONObject Id1Json = null, Id2Json = null;
    if (Id1 == entities.getJSONObject(0).getLong("Id")) {
      Id1Json = entities.getJSONObject(0);
      Id2Json = entities.getJSONObject(entities.length() - 1);
    } else {
      Id1Json = entities.getJSONObject(entities.length() - 1);
      Id2Json = entities.getJSONObject(0);
    }
    Set<Long> RId1 = new HashSet<Long>();
    Set<Long> Other1 = new HashSet<Long>();
    Set<Long> Other2 = new HashSet<Long>();
    Util.ParseJson(Id1Json, RId1, Other1, null);
    Util.ParseJson(Id2Json, null, Other2, null);

    expr = "RId=" + Id2 + "&count=10000&attributes=Id";
    json = SendRequset(httpclient, expr);
    entities = json.getJSONArray("entities");
    Set<Long> Id3s = new HashSet<Long>();
    for (int i = 0; i < entities.length(); ++i) {
      Id3s.add(entities.getJSONObject(i).getLong("Id"));
    }

    // 2-hop paths
    List<Long> middle = Util.Intersection(Other1, Other2);
    for (Long m : middle) {
      List<Long> element = new ArrayList<Long>();
      element.add(Id1);
      element.add(m);
      element.add(Id2);
      result.add(element);
    }
    middle = Util.Intersection(RId1, Id3s);
    for (Long m : middle) {
      List<Long> element = new ArrayList<Long>();
      element.add(Id1);
      element.add(m);
      element.add(Id2);
      result.add(element);
    }

    // 1-hop path and one kind of 3-hop paths
    if (RId1.contains(Id2)) {
      List<Long> element = new ArrayList<Long>();
      element.add(Id1);
      element.add(Id2);
      result.add(element);

      for (Long other : Other2) {
        List<Long> newElement = new ArrayList<Long>(element);
        newElement.add(other);
        result.add(newElement);
      }
    }

    // other 3-hop paths
    RId1.remove(Id2);
    int mod = 64;
    int n = RId1.size();
    if (n > 0) {
      List<Long> ids = new ArrayList<>(RId1);
      int begin = 0;
      while (true) {
        expr = Util.CreateOR(ids, begin, Math.min(begin + mod - 1, n - 1))
            + "&count=10000&attributes=Id,RId,F.FId,J.JId,C.CId,AA.AuId";
        json = SendRequset(httpclient, expr);
        entities = json.optJSONArray("entities");
        if (entities != null) {
          for (int i = 0; i < entities.length(); i++) {
            JSONObject obj = entities.getJSONObject(i);
            Long id = obj.getLong("Id");
            Set<Long> RId = new HashSet<>();
            Set<Long> Other = new HashSet<>();
            Util.ParseJson(obj, RId, Other, null);
            List<Long> common = Util.Intersection(RId, Id3s);
            for (Long rid : common) {
              List<Long> element = new ArrayList<>();
              element.add(Id1);
              element.add(id);
              element.add(rid);
              element.add(Id2);
              result.add(element);
            }
            common = Util.Intersection(Other, Other2);
            for (Long other : common) {
              List<Long> element = new ArrayList<>();
              element.add(Id1);
              element.add(id);
              element.add(other);
              element.add(Id2);
              result.add(element);
            }
          }

        }
        begin += mod;
        if (begin > n - 1) break;
      }
    }

    n = Id3s.size();
    if (n > 0) {
      List<Long> ids = new ArrayList<>(Id3s);
      int begin = 0;
      while (true) {
        expr = Util.CreateOR(ids, begin, Math.min(begin + mod - 1, n - 1))
            + "&count=10000&attributes=Id,F.FId,J.JId,C.CId,AA.AuId";
        json = SendRequset(httpclient, expr);
        entities = json.optJSONArray("entities");
        if (entities != null) {
          for (int i = 0; i < entities.length(); i++) {
            JSONObject obj = entities.getJSONObject(i);
            Long id = obj.getLong("Id");
            Set<Long> Other = new HashSet<>();
            Util.ParseJson(obj, null, Other, null);
            List<Long> common = Util.Intersection(Other, Other1);
            for (Long other : common) {
              List<Long> element = new ArrayList<>();
              element.add(Id1);
              element.add(other);
              element.add(id);
              element.add(Id2);
              result.add(element);
            }
          }
        }

        begin += mod;
        if (begin > n - 1) break;
      }
    }


    return result;
  }



  public static JSONObject SendRequset(HttpClient httpclient, String expr) {
    System.out.println(expr);
    ++reqNum;
    String response = MAGAPI.Get(httpclient, expr);
    // System.out.println(response);
    // error checking
    // while (response == null) response = MAGAPI.Get(httpclient, expr);
    // while(regex解析response的值为error) response = MAGAPI.Get(httpclient, expr);
    return new JSONObject(response);
  }

}
