package com.xiexin.bean;

import java.io.Serializable;

/**
 * jiaose_quanxian
 * @author 
 */
public class JiaoseQuanxian implements Serializable {
    private Integer jiaoseQuanxianId;

    private Integer jiaoseId;

    private Integer quanxianId;

    private static final long serialVersionUID = 1L;

    public Integer getJiaoseQuanxianId() {
        return jiaoseQuanxianId;
    }

    public void setJiaoseQuanxianId(Integer jiaoseQuanxianId) {
        this.jiaoseQuanxianId = jiaoseQuanxianId;
    }

    public Integer getJiaoseId() {
        return jiaoseId;
    }

    public void setJiaoseId(Integer jiaoseId) {
        this.jiaoseId = jiaoseId;
    }

    public Integer getQuanxianId() {
        return quanxianId;
    }

    public void setQuanxianId(Integer quanxianId) {
        this.quanxianId = quanxianId;
    }

    @Override
    public boolean equals(Object that) {
        if (this == that) {
            return true;
        }
        if (that == null) {
            return false;
        }
        if (getClass() != that.getClass()) {
            return false;
        }
        JiaoseQuanxian other = (JiaoseQuanxian) that;
        return (this.getJiaoseQuanxianId() == null ? other.getJiaoseQuanxianId() == null : this.getJiaoseQuanxianId().equals(other.getJiaoseQuanxianId()))
            && (this.getJiaoseId() == null ? other.getJiaoseId() == null : this.getJiaoseId().equals(other.getJiaoseId()))
            && (this.getQuanxianId() == null ? other.getQuanxianId() == null : this.getQuanxianId().equals(other.getQuanxianId()));
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((getJiaoseQuanxianId() == null) ? 0 : getJiaoseQuanxianId().hashCode());
        result = prime * result + ((getJiaoseId() == null) ? 0 : getJiaoseId().hashCode());
        result = prime * result + ((getQuanxianId() == null) ? 0 : getQuanxianId().hashCode());
        return result;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(getClass().getSimpleName());
        sb.append(" [");
        sb.append("Hash = ").append(hashCode());
        sb.append(", jiaoseQuanxianId=").append(jiaoseQuanxianId);
        sb.append(", jiaoseId=").append(jiaoseId);
        sb.append(", quanxianId=").append(quanxianId);
        sb.append(", serialVersionUID=").append(serialVersionUID);
        sb.append("]");
        return sb.toString();
    }
}