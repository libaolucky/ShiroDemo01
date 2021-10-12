package com.xiexin.bean;

import java.io.Serializable;

/**
 * jiao_se
 * @author 
 */
public class JiaoSe implements Serializable {
    private Integer jiaoSeId;

    private String jiaoSeName;

    private static final long serialVersionUID = 1L;

    public Integer getJiaoSeId() {
        return jiaoSeId;
    }

    public void setJiaoSeId(Integer jiaoSeId) {
        this.jiaoSeId = jiaoSeId;
    }

    public String getJiaoSeName() {
        return jiaoSeName;
    }

    public void setJiaoSeName(String jiaoSeName) {
        this.jiaoSeName = jiaoSeName;
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
        JiaoSe other = (JiaoSe) that;
        return (this.getJiaoSeId() == null ? other.getJiaoSeId() == null : this.getJiaoSeId().equals(other.getJiaoSeId()))
            && (this.getJiaoSeName() == null ? other.getJiaoSeName() == null : this.getJiaoSeName().equals(other.getJiaoSeName()));
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((getJiaoSeId() == null) ? 0 : getJiaoSeId().hashCode());
        result = prime * result + ((getJiaoSeName() == null) ? 0 : getJiaoSeName().hashCode());
        return result;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(getClass().getSimpleName());
        sb.append(" [");
        sb.append("Hash = ").append(hashCode());
        sb.append(", jiaoSeId=").append(jiaoSeId);
        sb.append(", jiaoSeName=").append(jiaoSeName);
        sb.append(", serialVersionUID=").append(serialVersionUID);
        sb.append("]");
        return sb.toString();
    }
}