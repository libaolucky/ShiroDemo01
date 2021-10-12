package com.xiexin.bean;

import java.io.Serializable;

/**
 * ren_jiao_se
 * @author 
 */
public class RenJiaoSe implements Serializable {
    private Integer renJiaoseId;

    private Integer renId;

    private Integer jiaoseId;

    private static final long serialVersionUID = 1L;

    public Integer getRenJiaoseId() {
        return renJiaoseId;
    }

    public void setRenJiaoseId(Integer renJiaoseId) {
        this.renJiaoseId = renJiaoseId;
    }

    public Integer getRenId() {
        return renId;
    }

    public void setRenId(Integer renId) {
        this.renId = renId;
    }

    public Integer getJiaoseId() {
        return jiaoseId;
    }

    public void setJiaoseId(Integer jiaoseId) {
        this.jiaoseId = jiaoseId;
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
        RenJiaoSe other = (RenJiaoSe) that;
        return (this.getRenJiaoseId() == null ? other.getRenJiaoseId() == null : this.getRenJiaoseId().equals(other.getRenJiaoseId()))
            && (this.getRenId() == null ? other.getRenId() == null : this.getRenId().equals(other.getRenId()))
            && (this.getJiaoseId() == null ? other.getJiaoseId() == null : this.getJiaoseId().equals(other.getJiaoseId()));
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((getRenJiaoseId() == null) ? 0 : getRenJiaoseId().hashCode());
        result = prime * result + ((getRenId() == null) ? 0 : getRenId().hashCode());
        result = prime * result + ((getJiaoseId() == null) ? 0 : getJiaoseId().hashCode());
        return result;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(getClass().getSimpleName());
        sb.append(" [");
        sb.append("Hash = ").append(hashCode());
        sb.append(", renJiaoseId=").append(renJiaoseId);
        sb.append(", renId=").append(renId);
        sb.append(", jiaoseId=").append(jiaoseId);
        sb.append(", serialVersionUID=").append(serialVersionUID);
        sb.append("]");
        return sb.toString();
    }
}