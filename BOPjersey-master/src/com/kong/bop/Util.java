package com.kong.bop;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.json.JSONArray;
import org.json.JSONObject;

public class Util {
  public static void ParseJson(JSONObject entity, Set<Long> RId, Set<Long> Other, Set<Long> AuIds) {
    if (Other != null) {
      JSONArray Fs = entity.optJSONArray("F");
      if (Fs != null) {
        for (int i = 0; i < Fs.length(); ++i) {
          Other.add(Fs.getJSONObject(i).getLong("FId"));
        }
      }
      JSONObject J = entity.optJSONObject("J");
      if (J != null) {
        Other.add(J.getLong("JId"));
      }
      JSONObject C = entity.optJSONObject("C");
      if (C != null) {
        Other.add(C.getLong("CId"));
      }
      JSONArray AAs = entity.optJSONArray("AA");
      if (AAs != null) {
        for (int i = 0; i < AAs.length(); i++) {
          Other.add(AAs.getJSONObject(i).getLong("AuId"));
          if (AuIds != null) AuIds.add(AAs.getJSONObject(i).getLong("AuId"));
        }
      }
    }

    if (RId != null) {
      JSONArray RIds = entity.optJSONArray("RId");
      if (RIds != null) {
        for (int i = 0; i < RIds.length(); ++i) {
          RId.add(RIds.getLong(i));
        }
      }
    }
  }

  public static List<Long> Intersection(Set<Long> s1, Set<Long> s2) {
    List<Long> common = new ArrayList<Long>();
    Set<Long> small = s1, big = s2;
    if (s1.size() > s2.size()) {
      small = s2;
      big = s1;
    }
    for (Long other : small) {
      if (big.contains(other)) common.add(other);
    }
    return common;
  }

  public static String CreateOR(List<Long> ids, int begin, int end) {
    if (begin == end) return "Id=" + ids.get(begin);
    int mid = (begin + end) / 2;
    return "Or(" + CreateOR(ids, begin, mid) + "," + CreateOR(ids, mid + 1, end) + ")";
  }

  public static Set<Long> GetAfIds(JSONArray entities, Long AuId) {
    Set<Long> result = new HashSet<>();
    for (int i = 0; i < entities.length(); i++) {
      JSONArray AAs = entities.getJSONObject(i).getJSONArray("AA");
      for (int j = 0; j < AAs.length(); j++) {
        JSONObject aa = AAs.getJSONObject(j);
        if (AuId.equals(aa.getLong("AuId"))) {
          Long afid = aa.optLong("AfId");
          if (afid != null) result.add(afid);
          break;
        }
      }
    }
    result.remove(new Long(0));
    return result;
  }

}
